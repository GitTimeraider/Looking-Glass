"""Does a vulnerability apply to the container at all: other operating system (Go advisories, NVD) and Go programs
that do not contain the vulnerable code."""
import asyncio
import base64
import io
import json
import os
import tarfile

import httpx
import pytest

from lookingglass import applicability as ap
from lookingglass import db
from lookingglass.config import Settings
from lookingglass.vulnscan import Policy, VulnScanner, safe_name, sources

DSN = os.environ.get("TEST_DATABASE_URL")

# the advisory from the report: Root.Mkdir / Root.MkdirAll, Windows only
GO_6604 = {"id": "GO-2026-6604", "aliases": ["CVE-2026-56857"], "affected": [
    {"package": {"ecosystem": "Go", "name": "stdlib"},
     "ecosystem_specific": {"imports": [{"path": "os", "symbols": ["Root.Mkdir", "Root.MkdirAll"], "goos": ["windows"]}]}}]}
# HTTP/2 server, every system
GO_6612 = {"id": "GO-2026-6612", "aliases": ["CVE-2026-78663"], "affected": [
    {"package": {"ecosystem": "Go", "name": "stdlib"},
     "ecosystem_specific": {"imports": [{"path": "net/http", "symbols": ["http2serverConn.processData"]}]}}]}


def go_program(*funcs: str) -> bytes:
    """Looks like a Go program to scan_go_program: build info marker and a NUL-separated function name table."""
    return b"\x7fELF....\xff Go buildinf:..." + b"\x00".join([b"", b"runtime.main", *(f.encode() for f in funcs), b""])


def test_go_advisory_platform():
    pk = ap.osv_go_packages(GO_6604)
    assert pk == {"stdlib": [{"path": "os", "symbols": ["Root.Mkdir", "Root.MkdirAll"], "goos": ["windows"], "goarch": []}]}
    live, why = ap.go_platform(pk["stdlib"], "linux", "amd64")
    assert live == [] and "only affects Windows" in why and "linux/amd64" in why
    assert ap.go_platform(pk["stdlib"], "windows", None)[0]  # a Windows image: it applies
    live, why = ap.go_platform(ap.osv_go_packages(GO_6612)["stdlib"], "linux", "amd64")
    assert live and why is None  # no goos: every system
    arm = [{"path": "crypto/x", "symbols": [], "goos": [], "goarch": ["arm64"]}]
    assert ap.go_platform(arm, "linux", "amd64")[1] and ap.go_platform(arm, "linux", "arm64")[0]
    assert ap.go_platform(arm, "linux", None)[0]  # architecture unknown: assume it applies


def test_scan_go_program():
    wanted = ap.wanted_symbols(ap.osv_go_packages(GO_6604)["stdlib"] + ap.osv_go_packages(GO_6612)["stdlib"])
    assert wanted == ["net/http:http2serverConn.processData", "os:Root.Mkdir", "os:Root.MkdirAll"]
    prog = go_program("os.Open", "os.(*Root).Open", "net/http.(*http2serverConn).processData")
    r = ap.scan_go_program(prog, wanted)
    assert r["valid"] and r["present"] == ["net/http:http2serverConn.processData"]  # Mkdir: not in the program
    # exact names: os.(*Root).MkdirAllX is another function; a closure of the function counts as the function
    assert not ap.scan_go_program(go_program("os.(*Root).MkdirAllX"), ["os:Root.MkdirAll"])["present"]
    assert ap.scan_go_program(go_program("os.(*Root).MkdirAll.func1"), ["os:Root.MkdirAll"])["present"]
    assert ap.scan_go_program(go_program("os.MkdirAll"), ["os:MkdirAll"])["present"]
    assert ap.scan_go_program(go_program("os.MkdirAll[...]"), ["os:MkdirAll"])["present"]  # generic
    assert ap.scan_go_program(go_program("golang.org/x/crypto/ssh.(*Client).Dial"), ["golang.org/x/crypto/ssh:*"])["present"]
    # not a Go program, or names unreadable (obfuscated): nothing can be concluded
    assert not ap.scan_go_program(b"\x7fELF plain C program", wanted)["valid"]
    assert not ap.scan_go_program(b"\xff Go buildinf:\x00a.b\x00", wanted)["valid"]


def _nvd(*configs):
    return {"vulnerabilities": [{"cve": {"id": "CVE-1", "configurations": list(configs)}}]}


APP = {"vulnerable": True, "criteria": "cpe:2.3:a:zoom:zoom:*:*:*:*:*:*:*:*"}


def _on(*os_cpes):
    return {"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [APP]},
                                         {"operator": "OR", "cpeMatch": [{"vulnerable": False, "criteria": c} for c in os_cpes]}]}


def test_nvd_platforms():
    win = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
    mac = "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"
    lin = "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"
    assert ap.nvd_other_os(_nvd(_on(win))) == ["Windows"]
    assert ap.nvd_other_os(_nvd(_on(win, mac))) == ["Windows", "macOS"]
    assert ap.nvd_other_os(_nvd(_on(win), _on(mac))) == ["Windows", "macOS"]
    assert ap.nvd_other_os(_nvd(_on(win, lin))) is None          # also on Linux
    assert ap.nvd_other_os(_nvd(_on(win), {"nodes": [{"cpeMatch": [APP]}]})) is None  # one configuration: everywhere
    assert ap.nvd_other_os(_nvd({"nodes": [{"cpeMatch": [APP]}]})) is None
    # a Windows build of a program (target_sw), and Windows itself
    build = {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:agent:*:*:*:*:*:windows:*:*"}
    assert ap.nvd_other_os(_nvd({"nodes": [{"cpeMatch": [build]}]})) == ["Windows"]
    assert ap.nvd_other_os(_nvd({"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": win}]}]})) == ["Windows"]
    # an OS NVD names that we don't know: can't conclude
    assert ap.nvd_other_os(_nvd(_on("cpe:2.3:o:someone:rtos:-:*:*:*:*:*:*:*"))) is None
    assert ap.nvd_other_os({"vulnerabilities": []}) is None and ap.nvd_other_os(_nvd()) is None


def test_verdicts_and_policy():
    adv = {"GO-2026-6604": {"packages": ap.osv_go_packages(GO_6604)}, "GO-2026-6612": {"packages": ap.osv_go_packages(GO_6612)}}
    f6604 = {"vuln": "CVE-2026-56857", "aliases": ["GO-2026-6604"], "package": "stdlib", "version": "go1.26.8",
             "pkg_type": "go-module", "locations": ["/usr/local/bin/syft"], "cvss": 9.8, "fix_versions": ["1.26.9"], "kev": True}
    f6612 = {**f6604, "vuln": "CVE-2026-78663", "aliases": ["GO-2026-6612"], "cvss": 9.1, "kev": False}
    plat = {"os": "linux", "arch": "amd64"}
    v = ap.verdict(f6604, "img", plat, adv, {}, {})
    assert v["status"] == "not_applicable" and "Windows" in v["text"]
    assert ap.verdict(f6612, "img", plat, adv, {}, {}) is None  # program not read yet: undecided
    wanted = ap.wanted_symbols(adv["GO-2026-6612"]["packages"]["stdlib"])
    progs = {"img|/usr/local/bin/syft": ap.scan_go_program(go_program("os.Open"), wanted)}
    v = ap.verdict(f6612, "img", plat, adv, {}, progs)
    assert v["status"] == "not_reachable" and "net/http.(*http2serverConn).processData" in v["text"]
    progs = {"img|/usr/local/bin/syft": ap.scan_go_program(go_program("net/http.(*http2serverConn).processData"), wanted)}
    assert ap.verdict(f6612, "img", plat, adv, {}, progs)["status"] == "reachable"
    # in two programs: not affected only when neither has it
    two = {**f6612, "locations": ["/a", "/b"]}
    progs = {"img|/a": ap.scan_go_program(go_program("os.Open"), wanted)}
    assert ap.verdict(two, "img", plat, adv, {}, progs) is None
    # NVD: a CPE-matched program finding for a Windows-only CVE; deb packages are left to the distribution
    win = {"vuln": "CVE-1", "cves": ["CVE-1"], "pkg_type": "binary", "package": "zoom"}
    assert ap.verdict(win, "i", plat, {}, {"CVE-1": {"other_os": ["Windows"]}}, {})["status"] == "not_applicable"
    assert ap.verdict({**win, "pkg_type": "deb"}, "i", plat, {}, {"CVE-1": {"other_os": ["Windows"]}}, {}) is None
    assert ap.verdict(win, "i", plat, {}, {"CVE-1": {"other_os": None}}, {}) is None
    # the alert rules and the page: not affected, also when actively exploited
    pol = Policy.of(Settings())
    f6604["applies"] = ap.verdict(f6604, "img", plat, adv, {}, {})
    alert, _, why = pol.judge(f6604, ["x"])
    assert not alert and why == "not affected: other operating system" and pol.hidden_by(f6604) == "not affected"
    assert Policy.of(Settings(vuln_hide_not_affected=False)).hidden_by(f6604) is None


def test_layer_lookup_from_the_sbom(tmp_path):
    manifest = {"layers": [{"digest": "sha256:blobA", "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"},
                           {"digest": "sha256:blobB", "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}
    config = {"rootfs": {"diff_ids": ["sha256:diffA", "sha256:diffB"]}}
    doc = {"source": {"metadata": {"os": "linux", "architecture": "arm64", "layers": [{"digest": "sha256:diffA"}, {"digest": "sha256:diffB"}],
                                   "manifest": base64.b64encode(json.dumps(manifest).encode()).decode(),
                                   "config": base64.b64encode(json.dumps(config).encode()).decode()}},
           "artifacts": [{"name": "stdlib", "version": "go1.26.8", "type": "go-module",
                          "locations": [{"path": "/usr/local/bin/syft", "layerID": "sha256:diffB"}]}]}
    img = ap.sbom_image(doc)
    assert img["os"] == "linux" and img["arch"] == "arm64"
    layer = ap.program_layers(doc, "stdlib", "go1.26.8", ["/usr/local/bin/syft"])["/usr/local/bin/syft"]
    assert ap.blob_of(img, layer) == "sha256:blobB" and ap.blob_of(img, "sha256:blobA") == "sha256:blobA"
    assert ap.blob_of(img, "sha256:unknown") is None
    # a program from a gzip layer, ./ prefixes and links handled
    path = tmp_path / "layer.tgz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in (("./usr/local/bin/syft", b"PROGRAM"), ("usr/bin/other", b"x")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        link = tarfile.TarInfo("usr/bin/link")
        link.type, link.linkname = tarfile.SYMTYPE, "other"
        tar.addfile(link)
    got = ap.read_programs(path, ["/usr/local/bin/syft", "/usr/bin/link", "/missing"])
    assert got == {"/usr/local/bin/syft": b"PROGRAM", "/usr/bin/link": None, "/missing": None}


def test_sources_for_the_new_kinds():
    srcs, err = sources(Settings())
    assert err is None and srcs["advisory"][0].url == "https://api.osv.dev/v1/vulns/{id}"
    assert "{cve}" in srcs["platform"][0].url
    # an own list from before these kinds existed: the built-in ones are added; 'kind: off' is respected
    own = sources(Settings(vuln_sources="kev: https://x.example/kev.json | text"))[0]
    assert own["advisory"] and own["platform"]
    assert sources(Settings(vuln_sources="kev: off\nadvisory: off\nplatform: off"))[0]["advisory"] == []
    from lookingglass.vulnscan import parse_sources
    with pytest.raises(ValueError, match=r"\{id\}"):
        parse_sources("advisory: https://x.example/vulns")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_whole_check_with_a_registry(tmp_path):
    """From findings to verdicts: the advisories are looked up, the program is read from its one image layer (through
    the registry's token login), the Windows-only CVE and the HTTP/2 one both end up 'not affected'."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w:gz") as tar:
        data = go_program("os.Open", "os.(*Root).Open")
        ti = tarfile.TarInfo("usr/local/bin/syft")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"{req.method} {req.url.host}{req.url.path}")
        if req.url.host == "osv.example":
            doc = {"GO-2026-6604": GO_6604, "GO-2026-6612": GO_6612}.get(req.url.path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=doc) if doc else httpx.Response(404)
        if req.url.host == "auth.example":
            return httpx.Response(200, json={"token": "T"})
        if req.url.host == "registry-1.docker.io":
            if req.headers.get("authorization") != "Bearer T":
                return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="https://auth.example/token",service="registry.docker.io",scope="repository:gittimeraider/looking-glass:pull"'})
            if req.url.path == "/v2/gittimeraider/looking-glass/blobs/sha256:blobB":
                return httpx.Response(200, content=layer.getvalue())
        return httpx.Response(404)

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, vuln_images, vuln_findings, vuln_cache, vuln_closed")
            await pool.execute("DELETE FROM kv WHERE key LIKE 'vulnscan:%'")
            s = Settings(vuln_scan_enabled=True, data_dir=str(tmp_path),
                         vuln_sources="kev: off\nepss: off\ncvss: off\nosv: off\nplatform: off\n"
                                      "advisory: https://osv.example/v1/vulns/{id}")
            sc = VulnScanner(s)
            key = "sha256:img"
            await pool.execute("INSERT INTO vuln_images (key, image, repo, digest, status, sbom_source, platform) VALUES "
                               "($1, 'gittimeraider/looking-glass:develop', 'docker.io/gittimeraider/looking-glass', 'sha256:img', "
                               "'ok', 'registry (exact digest)', $2)", key, {"os": "linux", "arch": "amd64"})
            for vid, alias, score in (("CVE-2026-56857", "GO-2026-6604", 9.8), ("CVE-2026-78663", "GO-2026-6612", 9.1)):
                await pool.execute(
                    "INSERT INTO vuln_findings (image_key, vuln, package, version, pkg_type, aliases, cves, cvss, fix_versions, "
                    "locations, severity) VALUES ($1, $2, 'stdlib', 'go1.26.8', 'go-module', $3, $4, $5, '{1.26.9}', "
                    "'{/usr/local/bin/syft}', 'Critical')", key, vid, [alias], [vid], score)
            manifest = {"layers": [{"digest": "sha256:blobA"}, {"digest": "sha256:blobB"}]}
            sbom = {"source": {"metadata": {"os": "linux", "architecture": "amd64",
                                            "layers": [{"digest": "sha256:diffA"}, {"digest": "sha256:diffB"}],
                                            "manifest": base64.b64encode(json.dumps(manifest).encode()).decode()}},
                    "artifacts": [{"name": "stdlib", "version": "go1.26.8", "type": "go-module",
                                   "locations": [{"path": "/usr/local/bin/syft", "layerID": "sha256:diffB"}]}]}
            (sc.base / "sbom").mkdir(parents=True)
            (sc.base / "sbom" / f"{safe_name(key)}.json").write_text(json.dumps(sbom))
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
                await sc.check_applies(client, sources(s)[0])
                n_calls = len(calls)
                await sc.check_applies(client, sources(s)[0])  # everything known: nothing asked again
                assert len(calls) == n_calls
            assert "GET registry-1.docker.io/v2/gittimeraider/looking-glass/blobs/sha256:blobB" in calls
            assert not any("blobA" in c for c in calls)  # only the layer with the program
            await sc.evaluate()
            rows = {r["vuln"]: r for r in await pool.fetch("SELECT vuln, applies, alerted, why, shown FROM vuln_findings")}
            assert rows["CVE-2026-56857"]["applies"]["status"] == "not_applicable"
            assert rows["CVE-2026-78663"]["applies"]["status"] == "not_reachable"
            assert all(not r["alerted"] and r["why"].startswith("not affected") and not r["shown"] for r in rows.values())
            prog = await pool.fetchval("SELECT value FROM vuln_cache WHERE kind = 'program'")
            assert prog["valid"] and prog["present"] == []
            assert not list((sc.base / "tmp").iterdir())  # the downloaded layer is not kept
            # the page: hidden from All, listed under Not affected
            from lookingglass.web.app import create_app
            ep = {r.path: r.endpoint for r in create_app(s, None).routes if getattr(r, "path", "").startswith("/api/vulns")}
            assert await ep["/api/vulns/findings"](image=None, show="all", q=None, limit=100) == []
            na = await ep["/api/vulns/findings"](image=None, show="notaffected", q=None, limit=100)
            assert {r["vuln"] for r in na} == {"CVE-2026-56857", "CVE-2026-78663"}
            # switched off: normal findings again
            s.vuln_check_applies = False
            await sc.evaluate()
            assert await pool.fetchval("SELECT count(*) FROM vuln_findings WHERE alerted") == 2
        finally:
            await db.close()

    asyncio.run(main())
