"""Container packages (Unraid › Packages): what is inside the image of every container - operating system packages,
libraries, language packages and the programs they are built into - read with Syft (included in the image).

An image's list is read only when you ask for it (Update all / Update on one image) or when the image changes
(a container runs a new image: new digest, or recreated when the digest is unknown). Nothing is read on a schedule.
Only the parts are listed; there is no vulnerability matching.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from . import db
from .config import Settings

log = logging.getLogger(__name__)

DOCKER_HUB = ("docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# ------------------------------------------------------------------ images ---
@dataclass(frozen=True)
class ImageName:
    registry: str
    repo: str
    tag: str | None
    digest: str | None

    @property
    def full(self) -> str:
        return f"{self.registry}/{self.repo}"

    def names(self) -> list[str]:
        """Ways to write this image, for name patterns (nextcloud*, */nextcloud*, lscr.io/linuxserver/*)."""
        short = self.repo[8:] if self.registry == "docker.io" and self.repo.startswith("library/") else self.repo
        out = [self.full, short, self.repo]
        if self.tag:
            out += [f"{self.full}:{self.tag}", f"{short}:{self.tag}"]
        return list(dict.fromkeys(out))


def parse_image(image: str) -> ImageName:
    ref = (image or "").strip()
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    if ref.rfind(":") > ref.rfind("/"):
        ref, tag = ref.rsplit(":", 1)
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first.lower(), ref.split("/", 1)[1]
    else:
        registry, repo = "docker.io", ref
    if registry in DOCKER_HUB:
        registry = "docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return ImageName(registry, repo.lower(), tag or (None if digest else "latest"), digest)


def patterns(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\n]+", text or "") if p.strip()]


def matches(pats: list[str], names: list[str]) -> bool:
    import fnmatch
    return any(fnmatch.fnmatch(n.lower(), p.lower()) for p in pats for n in names)


def parse_env(text: str) -> dict[str, str]:
    out = {}
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, v = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k.strip()):
            raise ValueError(f"line {n}: use NAME=value")
        out[k.strip()] = v.strip()
    return out


def safe_name(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:32]


# ------------------------------------------------------------------- Syft ---
class ToolError(RuntimeError):
    pass


async def run_tool(args: list[str], env: dict[str, str], timeout: float) -> bytes:
    """Run Syft; stdout, or ToolError with what went wrong (missing, timeout, its own error lines)."""
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                    stdin=asyncio.subprocess.DEVNULL, env=env)
    except FileNotFoundError as exc:
        raise ToolError(f"'{args[0]}' was not found - the Looking Glass image includes it; running from source, install "
                        "it or set its path under Settings › Unraid servers › Container packages") from exc
    except PermissionError as exc:
        raise ToolError(f"'{args[0]}' can't be run (permission denied)") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ToolError(f"{Path(args[0]).name} did not finish within {timeout / 60:.0f} minutes (Settings › Unraid "
                        "servers › Container packages › Time limit)") from exc
    if proc.returncode != 0:
        lines = [ln.strip() for ln in _ANSI.sub("", err.decode("utf-8", "replace")).splitlines() if ln.strip()]
        useful = [ln for ln in lines if re.search(r"error|fail|denied|unauthor|not found|no such|refused|timeout|manifest", ln, re.IGNORECASE)]
        raise ToolError(f"{Path(args[0]).name} exit {proc.returncode}: " + (" · ".join((useful or lines)[-3:]) or "no output")[:700])
    return out


def compact(doc: dict[str, Any]) -> dict[str, Any]:
    """Syft JSON -> what is kept and listed: {distro, os, arch, packages: [{name, version, type, language, locations}]}."""
    d = doc.get("distro") or {}
    meta = ((doc.get("source") or {}).get("metadata")) or {}
    distro = d.get("prettyName") or " ".join(x for x in (d.get("name") or d.get("id"), d.get("versionID") or d.get("version")) if x)
    pkgs = []
    for a in doc.get("artifacts") or []:
        if not a.get("name"):
            continue
        pkgs.append({"name": str(a["name"]), "version": str(a.get("version") or ""), "type": str(a.get("type") or ""),
                     "language": str(a.get("language") or ""),
                     "locations": list(dict.fromkeys(str(x.get("path")) for x in a.get("locations") or [] if x.get("path")))[:5]})
    return {"distro": distro or None, "os": meta.get("os") or None, "arch": meta.get("architecture") or None, "packages": pkgs}


@dataclass
class Target:
    key: str                     # digest, or image id / name:tag when the digest is unknown
    image: str                   # as the containers use it
    name: ImageName
    digest: str | None = None
    image_id: str | None = None
    docker_url: str | None = None
    containers: list[dict[str, Any]] = field(default_factory=list)
    local_only: bool = False     # built locally / no registry digest: only the Docker API can export it

    def created(self) -> str:
        """When its containers were (re)created: changes when Unraid updates a container whose digest is unknown."""
        return "|".join(sorted(str(c.get("created") or "") for c in self.containers))


# ------------------------------------------------------------- the reader ---
_LISTS: dict[str, tuple[float, dict[str, Any]]] = {}


class PackageReader:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.status: dict[str, Any] = {}
        self.wake = asyncio.Event()
        self.base = Path(settings.data_dir) / "packages"

    async def save_status(self, **kw: Any) -> None:
        self.status.update(kw)
        await db.kv_set("packages:status", self.status)

    def list_path(self, key: str) -> Path:
        return self.base / f"{safe_name(key)}.json"

    def tool_env(self) -> dict[str, str]:
        s = self.s
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY",
                                                             "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                                                             "SSL_CERT_FILE", "SSL_CERT_DIR")}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.setdefault("HOME", str(self.base))
        env.update({"SYFT_CHECK_FOR_APP_UPDATE": "false", "XDG_CACHE_HOME": str(self.base / "cache")})
        if s.pkg_registry_user.strip() and s.pkg_registry_password:
            host = (s.pkg_registry_host or "docker.io").strip()
            env["SYFT_REGISTRY_AUTH_AUTHORITY"] = "index.docker.io" if host in DOCKER_HUB else host
            env["SYFT_REGISTRY_AUTH_USERNAME"] = s.pkg_registry_user.strip()
            env["SYFT_REGISTRY_AUTH_PASSWORD"] = s.pkg_registry_password
        try:
            env.update(parse_env(s.pkg_tool_env))
        except ValueError:
            pass
        return env

    # ----------------------------------------------------------- inventory ---
    async def inventory(self) -> tuple[list[Target], bool]:
        """Images of the containers on your Unraid servers (+ exact digests from the Docker API); and whether every
        server could be listed (only then are images no container uses any more removed)."""
        targets: dict[str, Target] = {}
        inv: dict[str, Any] = {}
        all_ok = True
        excl = patterns(self.s.pkg_exclude)
        for srv in await db.pool().fetch("SELECT id, name, docker_url FROM unraid_servers WHERE enabled ORDER BY id"):
            snap = await db.get_snapshot(f"unraid:{srv['id']}:docker")
            st: dict[str, Any] = {"server": srv["name"], "containers": 0}
            if snap is None:
                st.update(ok=False, error="no container list from the Unraid API yet (Unraid › Overview › Connection)")
                inv[str(srv["id"])] = st
                all_ok = False
                continue
            details: dict[str, dict[str, Any]] = {}
            if srv["docker_url"]:
                try:
                    details = await self.docker_details(srv["docker_url"])
                    st["docker_api"] = "ok"
                except Exception as exc:  # noqa: BLE001
                    st["docker_api"] = f"{type(exc).__name__}: {exc}"[:300] + (
                        " - the docker-socket-proxy needs IMAGES=1" if isinstance(exc, httpx.HTTPStatusError) and
                        exc.response.status_code == 403 else "")
            else:
                st["docker_api"] = ("not set up: the registry's current image of each tag is read, which can differ "
                                    "from the one running - add a Docker API under Settings › Unraid servers")
            for c in snap:
                cname = str((c.get("names") or ["?"])[0]).lstrip("/")
                image = str(c.get("image") or "")
                if not image:
                    continue
                d = details.get(cname) or {}
                img_name = parse_image(d.get("image") if d.get("image") and not str(d["image"]).startswith("sha256:") else image)
                if excl and matches(excl, img_name.names() + [cname, image]):
                    continue
                digest = d.get("digest")
                key = digest or d.get("image_id") or img_name.full + ":" + (img_name.tag or "")
                t = targets.get(key)
                if t is None:
                    t = targets[key] = Target(key, image, img_name, digest=digest, image_id=d.get("image_id"),
                                              docker_url=srv["docker_url"] or None, local_only=bool(d) and not digest)
                t.containers.append({"server": srv["name"], "name": cname, "state": c.get("state"),
                                     "created": c.get("created")})
                st["containers"] += 1
            st["ok"] = True
            inv[str(srv["id"])] = st
        await self.save_status(inventory=inv)
        return list(targets.values()), all_ok

    async def docker_details(self, docker_url: str) -> dict[str, dict[str, Any]]:
        """{container name: {image, image_id, digest}} from a (read-only) Docker API."""
        out: dict[str, dict[str, Any]] = {}
        async with httpx.AsyncClient(base_url=docker_url.rstrip("/"), timeout=httpx.Timeout(20.0, connect=5.0)) as c:
            r = await c.get("/containers/json", params={"all": "1"})
            r.raise_for_status()
            images: dict[str, dict[str, Any]] = {}
            failed: list[Exception] = []
            containers = r.json()
            for ctr in containers:
                iid = ctr.get("ImageID")
                if iid and iid not in images:
                    try:
                        ri = await c.get(f"/images/{iid}/json")
                        ri.raise_for_status()
                        images[iid] = ri.json()
                    except httpx.HTTPStatusError as exc:
                        images[iid] = {}
                        failed.append(exc)
            if failed and not any(images.values()):
                raise failed[0]  # none at all: the proxy refuses /images (IMAGES=1 missing)
            for ctr in containers:
                iid = ctr.get("ImageID")
                info = images.get(iid) or {}
                name = parse_image(str(ctr.get("Image") or ""))
                digests = [d for d in info.get("RepoDigests") or [] if "@" in d]
                mine = [d for d in digests if parse_image(d).full == name.full]
                entry = {"image": ctr.get("Image"), "image_id": iid,
                         "digest": (mine or digests or [""])[0].split("@")[-1] or None}
                for n in ctr.get("Names") or []:
                    out[str(n).lstrip("/")] = entry
        return out

    def sources(self, t: Target) -> list[tuple[str, str, dict[str, str]]]:
        """(label, Syft source, extra env) in the order to try, per Settings › Image source."""
        mode = self.s.pkg_image_source
        out: list[tuple[str, str, dict[str, str]]] = []
        reg_digest = f"{t.name.full}@{t.digest}" if t.digest else None
        reg_tag = f"{t.name.full}:{t.name.tag}" if t.name.tag else None
        docker = None
        if t.docker_url and t.image_id:
            docker = ("Docker API export", f"docker:{t.image_id}",
                      {"DOCKER_HOST": re.sub(r"^https?://", "tcp://", t.docker_url.rstrip("/"))})
        if mode in ("auto", "registry") and reg_digest:
            out.append(("registry (exact digest)", f"registry:{reg_digest}", {}))
        if mode in ("auto", "docker") and docker:
            out.append(docker)
        if mode in ("auto", "registry") and not reg_digest and reg_tag and not t.local_only:
            out.append(("registry (current image of the tag)", f"registry:{reg_tag}", {}))
        return out

    async def read(self, t: Target) -> tuple[str, dict[str, Any]]:
        """Syft the image; (how it was read, compact list) - also written to its file."""
        env, path = self.tool_env(), self.list_path(t.key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".syft.tmp")
        errors = []
        for label, src, extra in self.sources(t):
            try:
                await run_tool([self.s.pkg_syft_path or "syft", "scan", src, "-o", f"syft-json={tmp}",
                                *shlex.split(self.s.pkg_syft_args or "")], {**env, **extra}, max(2, self.s.pkg_timeout) * 60.0)
                listed = compact(json.loads(tmp.read_text()))
                path.write_text(json.dumps(listed))
                return label, listed
            except (ToolError, ValueError, OSError) as exc:
                errors.append(f"{label}: {exc}")
            finally:
                tmp.unlink(missing_ok=True)
        if not errors:
            raise ToolError("no way to get this image: " + ("it has no registry digest (built locally?) and Image source "
                            "leaves out the Docker API" if t.local_only else "set Image source to auto"))
        raise ToolError(" · ".join(errors))

    # ----------------------------------------------------------------- run ---
    async def update(self, request: dict[str, Any] | None = None) -> None:
        """Find the images in use and read the ones that need it: all / one (asked for), else only new or changed
        images. Images no container uses any more are removed (when every server could be listed)."""
        started = time.time()
        await self.save_status(running=True, phase="listing containers", error=None)
        try:
            targets, all_ok = await self.inventory()
            pool = db.pool()
            rows = {r["key"]: dict(r) for r in await pool.fetch("SELECT * FROM image_packages")}
            want_all = bool((request or {}).get("all"))
            want_one = (request or {}).get("image")
            todo = []
            for t in targets:
                row = rows.get(t.key) or {}
                changed = not row or not self.list_path(t.key).exists() or (not t.digest and row.get("created") != t.created())
                if want_all or want_one == t.key or changed:
                    todo.append(t)
                await pool.execute(
                    "INSERT INTO image_packages (key, image, repo, digest, containers, seen_at) VALUES ($1, $2, $3, $4, $5, now()) "
                    "ON CONFLICT (key) DO UPDATE SET image = EXCLUDED.image, repo = EXCLUDED.repo, digest = EXCLUDED.digest, "
                    "containers = EXCLUDED.containers, seen_at = now()",
                    t.key, t.image, t.name.full, t.digest, [{k: v for k, v in c.items() if k != "created"} for c in t.containers])
            for i, t in enumerate(todo, 1):
                await self.save_status(phase=f"reading {t.image} ({i}/{len(todo)})")
                try:
                    how, listed = await self.read(t)
                    await pool.execute(
                        "UPDATE image_packages SET status = 'ok', error = NULL, read_at = now(), source = $2, packages = $3, "
                        "distro = $4, created = $5 WHERE key = $1", t.key, how, len(listed["packages"]), listed["distro"], t.created())
                except ToolError as exc:
                    await pool.execute("UPDATE image_packages SET status = 'error', error = $2, created = $3 WHERE key = $1",
                                       t.key, str(exc)[:1500], t.created())
                    log.warning("could not read the packages of %s: %s", t.image, exc)
            if all_ok:
                gone = [k for k in rows if k not in {t.key for t in targets}]
                if gone:
                    await pool.execute("DELETE FROM image_packages WHERE key = ANY($1::text[])", gone)
                    for k in gone:
                        self.list_path(k).unlink(missing_ok=True)
            await self.save_status(last_run=time.time(), read=len(todo), duration=round(time.time() - started), phase=None)
        except Exception as exc:
            log.exception("reading container packages failed")
            await self.save_status(error=f"{type(exc).__name__}: {exc}"[:600], phase=None)
        finally:
            await self.save_status(running=False)

    async def signature(self) -> str:
        """Which containers run which image, and since when (Unraid recreates a container when it updates it)."""
        parts = [self.s.pkg_exclude or ""]
        for r in await db.pool().fetch("SELECT id FROM unraid_servers WHERE enabled ORDER BY id"):
            for c in await db.get_snapshot(f"unraid:{r['id']}:docker") or []:
                parts.append(f"{r['id']}|{(c.get('names') or ['?'])[0]}|{c.get('image')}|{c.get('created')}")
        return hashlib.sha256("\n".join(sorted(parts)).encode()).hexdigest()

    async def tick(self) -> None:
        if not self.s.pkg_enabled:
            return
        req = await db.kv_get("packages:request")
        if req:
            await db.pool().execute("DELETE FROM kv WHERE key = 'packages:request'")
        sig = await self.signature()
        if req or sig != self.status.get("signature"):
            await self.save_status(signature=sig)
            await self.update(req)

    async def run(self) -> None:
        self.status = await db.kv_get("packages:status", {}) or {}
        if self.status.get("running"):
            await self.save_status(running=False, phase=None)  # restarted in the middle of a run
        while True:
            try:
                await self.tick()
            except Exception:
                log.exception("container packages loop failed")
            try:
                await asyncio.wait_for(self.wake.wait(), 60)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()


def listed(settings: Settings, key: str) -> dict[str, Any]:
    """The stored list of an image (cached until its file changes)."""
    path = Path(settings.data_dir) / "packages" / f"{safe_name(key)}.json"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {"distro": None, "packages": []}
    hit = _LISTS.get(str(path))
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"distro": None, "packages": []}
    _LISTS[str(path)] = (mtime, data)
    return data


# ---------------------------------------------- one-time cleanup (removed) ---
async def remove_vulnerability_scanner_leftovers(settings: Settings) -> None:
    """Once: what the removed container vulnerability scanner stored - its tables, settings and state, its open alerts
    (closed, kept for reference like other closed alerts) and /data/vulnscan (Grype's database, package lists)."""
    if await db.kv_get("cleanup:vulnscan-removed"):
        return
    pool = db.pool()
    async with pool.acquire() as con, con.transaction():
        for table in ("vuln_findings", "vuln_images", "vuln_cache", "vuln_closed", "vuln_repo_off"):
            await con.execute(f"DROP TABLE IF EXISTS {table}")
        await con.execute("DELETE FROM kv WHERE key LIKE 'vulnscan:%'")
        await con.execute("DELETE FROM app_settings WHERE key LIKE 'vuln\\_%'")
        await con.execute(
            "UPDATE alerts SET status = 'closed', close_reason = 'resolved', "
            "description = coalesce(description, '') || E'\\n\\nClosed: container vulnerability scanning was removed.' "
            "WHERE rule IN ('container_vulnerable', 'vuln_scan_problem') AND status <> 'closed'")
    leftovers = Path(settings.data_dir) / "vulnscan"
    if leftovers.is_dir():
        await asyncio.to_thread(shutil.rmtree, leftovers, True)
        log.info("removed %s (left over from the removed vulnerability scanner)", leftovers)
    await db.kv_set("cleanup:vulnscan-removed", {"at": datetime.now(timezone.utc).isoformat()})
