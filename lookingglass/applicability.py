"""Does a vulnerability apply to this container at all? (Vulnerabilities page: 'not affected')

Two checks, each based on facts, never on guesses from description text:

* Platform: the advisory itself says on which operating systems / processors the problem exists. Go advisories (OSV,
  ``GO-…`` ids) list it per vulnerable package (``goos`` / ``goarch``); NVD records a CVE as "application X running on
  Microsoft Windows" or for a Windows build of a program (``target_sw``). Only when every one of these says "not Linux"
  is the finding not applicable. A distribution's own packages (deb / rpm / apk) are not checked this way: their
  trackers already decide what affects their Linux build.
* Go: the advisory names the vulnerable functions. The Go linker leaves out every function a program can never call,
  and keeps the name of every function that is in the program (for stack traces, also when "stripped"). When none of
  the vulnerable functions is in the program, the vulnerable code is not in the container - the same check as Go's own
  ``govulncheck -mode=binary``. The program is read from the one image layer it is in.

Anything that can't be decided (no advisory data, program not readable, obfuscated names) stays a normal finding.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import tarfile
from pathlib import Path
from typing import Any

import httpx

GO_ID = re.compile(r"^GO-\d{4}-\d+$")
DISTRO_TYPES = {"deb", "rpm", "apk", "alpm", "portage"}
# NVD 'target_sw' / OS products that are not Linux
_OTHER_SW = {"windows": "Windows", "macos": "macOS", "mac_os_x": "macOS", "mac_os": "macOS", "iphone_os": "iOS",
             "ios": "iOS", "ipados": "iOS", "android": "Android", "watchos": "watchOS", "tvos": "tvOS"}
GOOS_NAMES = {"windows": "Windows", "darwin": "macOS", "ios": "iOS", "android": "Android", "freebsd": "FreeBSD",
              "openbsd": "OpenBSD", "netbsd": "NetBSD", "dragonfly": "DragonFly BSD", "solaris": "Solaris",
              "illumos": "illumos", "aix": "AIX", "plan9": "Plan 9", "js": "JavaScript / WebAssembly",
              "wasip1": "WASI", "linux": "Linux"}
MAX_LAYER = 2 * 1024 ** 3      # bytes downloaded for one layer at most
MAX_PROGRAM = 512 * 1024 ** 2  # bytes of one program read at most


# ----------------------------------------------------------------- Go (OSV) ---
def go_ids(f: dict[str, Any]) -> list[str]:
    return [i for i in [str(f.get("vuln") or ""), *(str(a) for a in f.get("aliases") or [])] if GO_ID.match(i)]


def osv_go_packages(doc: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """An OSV Go advisory -> {package or module: [{path, symbols, goos, goarch}]} (what is kept in the cache)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for a in doc.get("affected") or []:
        pkg = a.get("package") or {}
        if str(pkg.get("ecosystem") or "") != "Go" or not pkg.get("name"):
            continue
        imports = ((a.get("ecosystem_specific") or {}).get("imports")) or []
        out.setdefault(str(pkg["name"]), []).extend(
            {"path": str(i.get("path") or ""), "symbols": [str(s) for s in i.get("symbols") or []],
             "goos": [str(x) for x in i.get("goos") or []], "goarch": [str(x) for x in i.get("goarch") or []]}
            for i in imports if i.get("path"))
    return out


def _os_ok(imp: dict[str, Any], os_: str, arch: str | None) -> bool:
    if imp.get("goos") and os_ not in imp["goos"]:
        return False
    return not (arch and imp.get("goarch") and arch not in imp["goarch"])


def go_platform(imports: list[dict[str, Any]], os_: str, arch: str | None) -> tuple[list[dict[str, Any]], str | None]:
    """(the imports that exist on this platform, why none does - or None)."""
    live = [i for i in imports if _os_ok(i, os_, arch)]
    if live or not imports:
        return live, None
    systems = sorted({GOOS_NAMES.get(g, g) for i in imports for g in i.get("goos") or []})
    archs = sorted({a for i in imports for a in i.get("goarch") or []})
    only = " / ".join(systems) if systems else ""
    if archs and not systems:
        only = "the processor(s) " + ", ".join(archs)
    elif archs:
        only += " on " + ", ".join(archs)
    return [], f"the Go advisory says it only affects {only}; this image is {os_}" + (f"/{arch}" if arch else "")


def go_names(path: str, symbol: str) -> list[str]:
    """How the Go linker names a function of package ``path``: Root.Mkdir -> os.(*Root).Mkdir or os.Root.Mkdir."""
    if not symbol:
        return []
    if "." in symbol:
        typ, meth = symbol.split(".", 1)
        return [f"{path}.(*{typ}).{meth}", f"{path}.{typ}.{meth}", f"{path}.(*{typ}[...]).{meth}", f"{path}.{typ}[...].{meth}"]
    return [f"{path}.{symbol}", f"{path}.{symbol}[...]"]


def wanted_symbols(imports: list[dict[str, Any]]) -> list[str]:
    """What to look for: 'path:Symbol', or 'path:*' when the whole package is affected."""
    out = []
    for i in imports:
        out += [f"{i['path']}:{s}" for s in i.get("symbols") or []] or [f"{i['path']}:*"]
    return sorted(set(out))


def scan_go_program(data: bytes, wanted: list[str]) -> dict[str, Any]:
    """Which of ``wanted`` ('path:Symbol' / 'path:*') a Go program contains. Function names sit NUL-separated in the
    program's function table (also in stripped programs); closures ('.func1') and method values ('-fm') count too.
    {"valid": False} when this is not a Go program with readable names (then nothing can be concluded)."""
    if b"\xff Go buildinf:" not in data or b"\x00runtime.main\x00" not in data:
        return {"valid": False, "checked": wanted, "present": []}
    present = []
    for w in wanted:
        path, _, sym = w.partition(":")
        if sym == "*":
            hit = b"\x00" + path.encode() + b"." in data or b"\x00" + path.encode() + b".(" in data
        else:
            hit = any(b"\x00" + n.encode() + end in data for n in go_names(path, sym)
                      for end in (b"\x00", b".func", b"-fm", b".gowrap"))
        if hit:
            present.append(w)
    return {"valid": True, "checked": wanted, "present": present}


def pretty(w: str) -> str:
    path, _, sym = w.partition(":")
    return f"package {path}" if sym == "*" else go_names(path, sym)[0]


# ----------------------------------------------------------------------- NVD ---
def _cpe(criteria: str) -> list[str]:
    parts = str(criteria or "").split(":")
    return parts + [""] * (13 - len(parts))


def _os_family(criteria: str) -> str | None:
    """'linux', another OS name, or None (not an operating system / can't tell)."""
    p = _cpe(criteria)
    if p[2] != "o":
        return None
    vendor, product = p[3].lower(), p[4].lower()
    if "linux" in product or vendor in ("linux", "debian", "canonical", "redhat", "fedoraproject", "suse", "opensuse",
                                        "alpinelinux", "archlinux", "gentoo", "centos", "rockylinux", "almalinux"):
        return "linux"
    if vendor == "microsoft" and product.startswith("windows"):
        return "Windows"
    if vendor == "apple":
        return _OTHER_SW.get(product, "Apple " + product)
    if vendor == "google" and product == "android":
        return "Android"
    return {"freebsd": "FreeBSD", "openbsd": "OpenBSD", "netbsd": "NetBSD"}.get(product)


def nvd_other_os(doc: dict[str, Any]) -> list[str] | None:
    """The operating systems an NVD CVE is restricted to, when it is restricted to systems other than Linux in every
    configuration; None when any configuration applies to Linux, to every system, or can't be read."""
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return None
    configs = ((vulns[0] or {}).get("cve") or {}).get("configurations") or []
    if not configs:
        return None
    found: set[str] = set()
    for cfg in configs:
        nodes = cfg.get("nodes") or []
        req: set[str] | None = None
        if str(cfg.get("operator") or "").upper() == "AND":  # "X running on / with Y"
            for n in nodes:
                ms = n.get("cpeMatch") or []
                if ms and not n.get("negate") and not any(m.get("vulnerable") for m in ms):
                    fams = {_os_family(m.get("criteria")) for m in ms}
                    if fams and None not in fams:
                        req = fams if req is None else req | fams
        vul = [m for n in nodes for m in n.get("cpeMatch") or [] if m.get("vulnerable")]
        if req is None and vul:
            # the vulnerable thing is the OS itself, or a build for one: cpe ...:<target_sw>:...
            fams = set()
            for m in vul:
                p = _cpe(m.get("criteria"))
                fam = _os_family(m.get("criteria")) or _OTHER_SW.get(p[10].lower())
                fams.add(fam)
            if None not in fams:
                req = fams
        if req is None or "linux" in req:
            return None
        found |= req
    return sorted(found) or None


# --------------------------------------------------------- reading a program ---
def sbom_image(doc: dict[str, Any]) -> dict[str, Any]:
    """os / architecture and the layer blobs of the image an SBOM (Syft JSON) was made from."""
    meta = ((doc.get("source") or {}).get("metadata")) or {}
    out: dict[str, Any] = {"os": str(meta.get("os") or "linux").lower(), "arch": meta.get("architecture") or None}
    try:
        man = meta.get("manifest")
        man = json.loads(base64.b64decode(man)) if isinstance(man, str) else (man or {})
        cfg = meta.get("config")
        cfg = json.loads(base64.b64decode(cfg)) if isinstance(cfg, str) else (cfg or {})
    except (ValueError, TypeError):
        man, cfg = {}, {}
    out["blobs"] = [str(lay.get("digest")) for lay in man.get("layers") or [] if lay.get("digest")]
    out["blob_types"] = [str(lay.get("mediaType") or "") for lay in man.get("layers") or [] if lay.get("digest")]
    out["diff_ids"] = list((cfg.get("rootfs") or {}).get("diff_ids") or [])
    out["layers"] = [str(lay.get("digest")) for lay in meta.get("layers") or []]
    return out


def program_layers(doc: dict[str, Any], package: str, version: str, paths: list[str]) -> dict[str, str]:
    """{program path: layer id it is in} for the Go package ``package`` ``version`` at ``paths`` (from the SBOM)."""
    out: dict[str, str] = {}
    for a in doc.get("artifacts") or []:
        if a.get("type") != "go-module" or a.get("name") != package or str(a.get("version") or "") != version:
            continue
        for loc in a.get("locations") or []:
            p, lay = loc.get("path"), loc.get("layerID")
            if p in paths and lay:
                out[p] = str(lay)
    return out


def blob_of(img: dict[str, Any], layer_id: str) -> str | None:
    """The registry blob (compressed layer) of a layer Syft names by its id (diff id or blob digest)."""
    if layer_id in img["blobs"]:
        return layer_id
    for lst in (img["layers"], img["diff_ids"]):
        if layer_id in lst:
            i = lst.index(layer_id)
            if i < len(img["blobs"]):
                return img["blobs"][i]
    return None


async def registry_get(client: httpx.AsyncClient, registry: str, repo: str, path: str, settings: Any,
                       accept: str = "", stream_to: Path | None = None, max_bytes: int = MAX_LAYER) -> bytes | None:
    """GET /v2/<repo>/<path> from a registry, anonymous or with Settings › Registry login (bearer token flow)."""
    from .vulnscan import (
        DOCKER_HUB,  # here, not at the top: vulnscan imports this module
    )
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    url = f"https://{host}/v2/{repo}/{path}"
    headers = {"Accept": accept} if accept else {}

    async def once(h: dict[str, str]) -> httpx.Response | None:
        if stream_to is None:
            return await client.get(url, headers=h)
        async with client.stream("GET", url, headers=h) as r:
            if r.status_code != 200:
                await r.aread()
                return r
            size = 0
            fh = await asyncio.to_thread(open, stream_to, "wb")  # disk writes off the event loop
            try:
                async for chunk in r.aiter_bytes(1 << 20):
                    size += len(chunk)
                    if size > max_bytes:
                        raise RuntimeError(f"layer larger than {max_bytes // 1024 ** 2} MB - not downloaded")
                    await asyncio.to_thread(fh.write, chunk)
            finally:
                await asyncio.to_thread(fh.close)
            return None

    r = await once(headers)
    if r is not None and r.status_code == 401 and "bearer" in r.headers.get("www-authenticate", "").lower():
        params = dict(re.findall(r'(\w+)="([^"]*)"', r.headers["www-authenticate"]))
        realm = params.pop("realm", "")
        auth = None
        login = (getattr(settings, "vuln_registry_host", "") or "docker.io").strip()
        if settings.vuln_registry_user and settings.vuln_registry_password and (
                login == registry or (login in DOCKER_HUB and registry == "docker.io")):
            auth = (settings.vuln_registry_user, settings.vuln_registry_password)
        t = await client.get(realm, params=params, auth=auth)
        t.raise_for_status()
        token = t.json().get("token") or t.json().get("access_token")
        r = await once({**headers, "Authorization": f"Bearer {token}"})
    if r is None:
        return b""
    r.raise_for_status()
    return r.content


def read_programs(layer_file: Path, paths: list[str], max_bytes: int = MAX_PROGRAM) -> dict[str, bytes | None]:
    """The files at ``paths`` from a layer tarball (gzip, zstd or plain): {path: content, or None when it is not a
    regular file in this layer}."""
    want = {p.lstrip("/"): p for p in paths}
    out: dict[str, bytes | None] = {p: None for p in paths}
    with tarfile.open(layer_file, "r:*") as tar:
        for m in tar:
            name = m.name.removeprefix("./").lstrip("/")
            if name in want and m.isreg() and m.size <= max_bytes:
                fh = tar.extractfile(m)
                out[want[name]] = fh.read() if fh else None
    return out


def verdict(f: dict[str, Any], image_key: str, platform: dict[str, Any] | None, advisories: dict[str, Any],
            platforms: dict[str, Any], programs: dict[str, Any]) -> dict[str, Any] | None:
    """Does finding ``f`` apply? {"status": not_applicable | not_reachable | reachable, "text": ...}, or None when it
    can't be decided (then it is a normal finding). Only from looked-up facts (caches), see the module text."""
    os_ = str((platform or {}).get("os") or "linux").lower()
    arch = (platform or {}).get("arch") or None
    if f.get("pkg_type") == "go-module":
        imports: list[dict[str, Any]] = []
        for gid in go_ids(f):
            imports += ((advisories.get(gid) or {}).get("packages") or {}).get(str(f.get("package") or ""), [])
        if not imports:
            return None
        live, why = go_platform(imports, os_, arch)
        if why:
            return {"status": "not_applicable", "text": why[0].upper() + why[1:] + "."}
        wanted = wanted_symbols(live)
        locs = [str(x) for x in f.get("locations") or []]
        if not locs:
            return None
        present, unknown = [], []
        for loc in locs:
            c = programs.get(f"{image_key}|{loc}") or {}
            if not c.get("valid") or not set(wanted) <= set(c.get("checked") or []):
                unknown.append(loc)
            else:
                present += [(loc, w) for w in wanted if w in c.get("present") or []]
        names = ", ".join(pretty(w) for w in wanted[:3]) + (f" (+{len(wanted) - 3} more)" if len(wanted) > 3 else "")
        if present:
            loc, w = present[0]
            return {"status": "reachable", "text": f"{loc} contains the vulnerable code ({pretty(w)})."}
        if unknown:
            return None
        progs = ", ".join(locs[:3])
        return {"status": "not_reachable",
                "text": f"The vulnerable code ({names}) is not in {progs}: Go leaves out every function a program can "
                        "never call, so this program can't run it."}
    if f.get("pkg_type") in DISTRO_TYPES or os_ != "linux":
        return None
    cves = [str(c) for c in f.get("cves") or []]
    other = [((platforms.get(c) or {}).get("other_os")) for c in cves]
    if cves and all(other):
        systems = sorted({x for lst in other for x in lst})
        return {"status": "not_applicable",
                "text": f"NVD lists {', '.join(cves[:2])} only for {' / '.join(systems)} (running on it, or a build "
                        f"for it); this image is Linux."}
    return None
