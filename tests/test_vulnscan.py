import asyncio
import gzip
import json
import os
import stat
import sys
import textwrap
import time
from datetime import date

import httpx
import pytest

from lookingglass import app_config, db
from lookingglass.config import Settings
from lookingglass.vulnscan import (Policy, Source, VulnScanner, cvss3_score, extract_cvss, extract_epss, extract_kev,
                                   jpath, level_of, osv_findings, parse_app_checks, parse_grype, parse_ignore, parse_image,
                                   parse_sources, sources)

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
ALL_OFF = "kev: off\nepss: off\ncvss: off\nosv: off"


def test_json_paths():
    doc = {"a": {"b": [{"c": 1}, {"c": 2}, {"d": 3}]}, "m": {"x": {"v": 5}, "y": {"v": 6}}}
    assert jpath(doc, "a.b[].c") == [1, 2]
    assert jpath(doc, "a.b[1].c") == [2]
    assert jpath(doc, "m.*.v") == [5, 6]
    assert jpath(doc, "a.missing[].c") == [] and jpath(doc, "a.b[9].c") == []
    assert jpath([1, 2], "[]") == [1, 2] and jpath(doc, "$.a.b[0].c") == [1]


def test_cvss3_scores():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N") == 5.4
    assert cvss3_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 7.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_score("CVSS:4.0/AV:N/AC:L") is None and cvss3_score("garbage") is None


def test_built_in_sources_parse_and_errors_name_the_line():
    srcs, err = sources(Settings())
    assert err is None and [s.kind for k in ("kev", "epss", "cvss", "osv") for s in srcs[k]] == ["kev", "kev", "epss", "cvss", "osv"]
    assert srcs["epss"][0].args == ["data[]", "cve", "epss", "percentile"]
    assert len(srcs["cvss"][0].args) == 3 and srcs["osv"][0].method == "POST"
    # empty = built-in list; your own list replaces it, 'off' switches a kind off
    assert sources(Settings(vuln_sources=""))[0]["kev"]
    own = parse_sources("kev: https://mirror.example/kev.csv | csv cveID\nepss: off\n# comment\n")
    assert own["kev"][0].fmt == "csv" and own["epss"] == [] and own["cvss"] == []
    assert parse_sources("kev: POST https://x.example/q | text")["kev"][0].method == "POST"
    for bad, word in [("kev https://x", "line 1"), ("foo: https://x", "kind"), ("kev: ftp://x", "http"),
                      ("kev: https://x | xml a", "format"), ("epss: https://x | json data[]", "argument"),
                      ("cvss: https://x/cve | json a.b", "{cve}"), ("\nkev: https://x | csv", "line 2")]:
        with pytest.raises(ValueError, match=word):
            parse_sources(bad)
    # a broken saved list falls back to the built-in one and says why
    assert sources(Settings(vuln_sources="kev: nonsense"))[1]


def test_kev_formats():
    js = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2024-4577"}, {"cveID": "junk"}]}).encode()
    assert extract_kev(Source("kev", "u", fmt="json", args=["vulnerabilities[].cveID"]), js) == {"CVE-2021-44228", "CVE-2024-4577"}
    csv_ = b"cveID,vendorProject\nCVE-2021-44228,Apache\ncve-2024-4577,PHP\n"
    assert extract_kev(Source("kev", "u", fmt="csv", args=["cveID"]), csv_) == {"CVE-2021-44228", "CVE-2024-4577"}
    # text: every CVE id, whatever the format became
    assert extract_kev(Source("kev", "u"), b"<html>CVE-2021-44228 and cve-2024-4577</html>") == {"CVE-2021-44228", "CVE-2024-4577"}


def test_epss_formats():
    js = json.dumps({"data": [{"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.999"}]}).encode()
    assert extract_epss(Source("epss", "u", fmt="json", args=["data[]", "cve", "epss", "percentile"]), js) == \
        {"CVE-2021-44228": (0.944, 0.999)}
    assert extract_epss(Source("epss", "u"), js)["CVE-2021-44228"][0] == 0.944  # default format
    gz = gzip.compress(b"#model_version:v2025,score_date:2026-11-05\ncve,epss,percentile\nCVE-2024-4577,0.9,0.99\n")
    assert extract_epss(Source("epss", "u", fmt="csv", args=["cve", "epss", "percentile"]), gz) == {"CVE-2024-4577": (0.9, 0.99)}


def test_cvss_lookup_takes_the_highest_score_at_the_paths():
    nvd = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}},
                                                                      {"cvssData": {"baseScore": 7.5}}],
                                                    "cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]}}}]}
    src = parse_sources(Settings().vuln_sources)["cvss"][0]
    assert extract_cvss(src, json.dumps(nvd).encode()) == 9.8
    assert extract_cvss(src, b'{"vulnerabilities": []}') is None


def test_image_names():
    n = parse_image("nextcloud:30-apache")
    assert (n.registry, n.repo, n.tag, n.digest) == ("docker.io", "library/nextcloud", "30-apache", None)
    assert "nextcloud" in n.names() and "docker.io/library/nextcloud" in n.names()
    n = parse_image("lscr.io/linuxserver/nextcloud")
    assert (n.registry, n.repo, n.tag) == ("lscr.io", "linuxserver/nextcloud", "latest")
    n = parse_image("localhost:5000/team/app@sha256:abc")
    assert (n.registry, n.repo, n.tag, n.digest) == ("localhost:5000", "team/app", None, "sha256:abc")
    assert parse_image("index.docker.io/jellyfin/jellyfin:10.9").full == "docker.io/jellyfin/jellyfin"


def test_ignore_rules_and_policy():
    rules = parse_ignore("CVE-2024-1 on nextcloud*  # accepted\npkg:perl-*\nCVE-2023-* until 2026-01-01")
    assert [r.what for r in rules] == ["CVE-2024-1", "pkg:perl-*", "CVE-2023-*"] and rules[0].where == ["nextcloud*"]
    with pytest.raises(ValueError, match="line 1"):
        parse_ignore("CVE-1 until tomorrow")
    pol = Policy(min_cvss=7.0, kev_always=True, epss_min=0.5, only_fixed=True, ignore=rules)
    f = {"vuln": "CVE-2024-1", "package": "x", "cvss": 9.8, "fix_versions": ["2"], "aliases": []}
    assert pol.judge(f, ["nextcloud"])[1] and pol.judge(f, ["mariadb"])[0]  # the exception is only for nextcloud
    assert pol.judge({**f, "vuln": "CVE-9", "package": "perl-base"}, ["x"])[2] == "ignored"
    old = {**f, "vuln": "CVE-2023-5"}
    assert not pol.judge(old, ["x"], date(2025, 6, 1))[0] and pol.judge(old, ["x"], date(2026, 6, 1))[0]  # 'until' ran out
    assert not pol.judge({**f, "vuln": "CVE-1", "cvss": 6.9}, ["x"])[0]
    assert pol.judge({**f, "vuln": "CVE-1", "cvss": 3.0, "epss": 0.6}, ["x"])[2].startswith("EPSS")
    nofix = {**f, "vuln": "CVE-1", "fix_versions": [], "fix_state": "not-fixed"}
    assert pol.judge(nofix, ["x"])[2] == "no fixed version yet"
    assert pol.judge({**nofix, "kev": True}, ["x"])[0]  # actively exploited: always
    assert pol.judge({**f, "vuln": "CVE-1", "cvss": None, "severity": "High"}, ["x"])[0]  # severity word estimate
    assert level_of({"kev": True, "cvss": 2}) == "critical" and level_of({"cvss": 7.5}) == "high"


def test_app_checks():
    chk = parse_app_checks(Settings().vuln_app_checks)
    assert chk[0].source == "env" and chk[0].name == "NEXTCLOUD_VERSION" and chk[0].package == "nextcloud/server"
    assert chk[0].version({"env": {"NEXTCLOUD_VERSION": "30.0.2.2"}}) == ("30.0.2.2", "environment variable NEXTCLOUD_VERSION")
    ls = chk[1].version({"labels": {"org.opencontainers.image.version": "30.0.2-ls123"}})
    assert ls[0] == "30.0.2"
    c = parse_app_checks(r"gitea/gitea | tag /^v?(\d+\.\d+)/ | Go code.gitea.io/gitea")[0]
    assert c.version({"tag": "v1.22.3-rootless"})[0] == "1.22"
    p = parse_app_checks("php* | package php-cli | Packagist php")[0]
    assert p.version({"packages": [{"name": "php-cli", "version": "8.1.0"}]})[0] == "8.1.0"
    assert p.version({"packages": []}) == (None, "package php-cli")
    for bad in ["a | env X", "a | foo X | Packagist x", "a | env | Packagist x", "a | tag /(/ | Go x", "a | env X | Packagist"]:
        with pytest.raises(ValueError, match="line 1"):
            parse_app_checks(bad)


GRYPE_DOC = {
    "matches": [
        {"vulnerability": {"id": "CVE-2024-4577", "severity": "Critical", "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
                           "cvss": [{"source": "nvd@nist.gov", "type": "Primary", "version": "3.1",
                                     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}}],
                           "knownExploited": [{"cve": "CVE-2024-4577"}], "epss": [{"cve": "CVE-2024-4577", "epss": 0.94, "percentile": 0.99}],
                           "fix": {"versions": ["8.1.29"], "state": "fixed"}},
         "relatedVulnerabilities": [],
         "artifact": {"name": "php-cli", "version": "8.1.0", "type": "binary", "locations": [{"path": "/usr/local/bin/php"}]}},
        {"vulnerability": {"id": "CVE-2023-0001", "severity": "Medium", "cvss": [], "fix": {"versions": [], "state": "not-fixed"}},
         "relatedVulnerabilities": [{"id": "CVE-2023-0001", "cvss": [{"source": "nvd@nist.gov", "version": "3.1",
                                                                     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                                                     "metrics": {}}]}],
         "artifact": {"name": "openssl", "version": "3.0.11-1", "type": "deb", "locations": [{"path": "/var/lib/dpkg/status"}]}},
        {"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "High", "fix": {"versions": ["2.1.0"], "state": "fixed"},
                           "cvss": [{"version": "2.0", "metrics": {"baseScore": 10}}]},
         "relatedVulnerabilities": [{"id": "CVE-2023-0002", "cvss": [{"source": "nvd@nist.gov", "version": "3.1", "metrics": {"baseScore": 7.5}}]}],
         "artifact": {"name": "guzzlehttp/guzzle", "version": "2.0.0", "type": "php-composer",
                      "locations": [{"path": "/var/www/html/3rdparty/composer/installed.json"}]}},
        # same vulnerability + package found at a second place: one finding, both locations
        {"vulnerability": {"id": "CVE-2024-4577", "fix": {"versions": ["8.1.29"], "state": "fixed"}},
         "artifact": {"name": "php-cli", "version": "8.1.0", "type": "binary", "locations": [{"path": "/usr/bin/php"}]}},
        {"vulnerability": {}, "artifact": {}},  # broken entry: skipped
    ],
    "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-05T00:00:00Z"}}},
}


def test_parse_grype_output():
    fs = {f["vuln"]: f for f in parse_grype(GRYPE_DOC)}
    assert set(fs) == {"CVE-2024-4577", "CVE-2023-0001", "GHSA-aaaa-bbbb-cccc"}
    php = fs["CVE-2024-4577"]
    assert php["cvss"] == 9.8 and php["kev"] and php["epss"] == 0.94 and php["fix_versions"] == ["8.1.29"]
    assert php["locations"] == ["/usr/local/bin/php", "/usr/bin/php"]  # in the order found
    assert fs["CVE-2023-0001"]["cvss"] == 5.4 and fs["CVE-2023-0001"]["fix_state"] == "not-fixed"  # score from the vector
    gh = fs["GHSA-aaaa-bbbb-cccc"]
    assert gh["cvss"] == 7.5 and gh["cves"] == ["CVE-2023-0002"] and "CVE-2023-0002" in gh["aliases"]  # CVSS 2 ignored


def test_osv_findings():
    chk = parse_app_checks("nextcloud | env V | Packagist nextcloud/server")[0]
    doc = {"vulns": [{"id": "GHSA-1111-2222-3333", "aliases": ["CVE-2024-9999"], "summary": "Login bypass",
                      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                      "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "30.0.4"}]}]}]},
                     {"id": "GHSA-4444", "database_specific": {"severity": "MODERATE"}, "affected": []}]}
    a, b = osv_findings(doc, chk, "30.0.1")
    assert a["vuln"] == "CVE-2024-9999" and a["cvss"] == 9.8 and a["fix_versions"] == ["30.0.4"] and "GHSA-1111-2222-3333" in a["aliases"]
    assert b["vuln"] == "GHSA-4444" and b["cvss"] is None and b["severity"] == "Moderate" and a["package"] == "nextcloud/server"


def test_settings_validation():
    f = app_config.BY_KEY
    with pytest.raises(app_config.SettingsError, match="Sources: line 1"):
        app_config._coerce(f["vuln_sources"], "kev https://x")
    with pytest.raises(app_config.SettingsError, match="Minimum CVSS score for an alert"):
        app_config._coerce(f["vuln_min_cvss"], "11")
    with pytest.raises(app_config.SettingsError, match="EPSS"):
        app_config._coerce(f["vuln_epss_min"], "2")
    assert app_config._coerce(f["vuln_epss_min"], "10%") == "10%"
    with pytest.raises(app_config.SettingsError, match="Exceptions"):
        app_config._coerce(f["vuln_ignore"], "CVE-1 until never")
    with pytest.raises(app_config.SettingsError, match="NAME=value"):
        app_config._coerce(f["vuln_tool_env"], "just text")
    with pytest.raises(app_config.SettingsError, match="Extra Grype arguments"):
        app_config._coerce(f["vuln_grype_args"], "--exclude 'unclosed")
    assert app_config._coerce(f["vuln_sources"], "") == ""


# ------------------------------------------------------------ with a database ---
FAKE_TOOL = textwrap.dedent('''\
    #!PYTHON
    import json, os, sys
    from datetime import datetime, timezone
    name, args = os.path.basename(sys.argv[0]), sys.argv[1:]
    if args[:1] == ["version"]:
        print(json.dumps({"application": name, "version": "9.9.9"})); sys.exit(0)
    if name == "grype":
        if args[:2] == ["db", "update"]:
            if os.environ.get("FAKE_DB_FAIL"):
                sys.stderr.write("[0000] ERROR unable to update vulnerability database: Forbidden\\n"); sys.exit(1)
            sys.exit(0)
        if args[:2] == ["db", "status"]:
            print(json.dumps({"schemaVersion": "v6.0.2", "built": os.environ.get("FAKE_DB_BUILT") or
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "valid": True})); sys.exit(0)
        print(open(os.environ["FAKE_GRYPE_DOC"]).read()); sys.exit(0)
    if name == "syft":
        if os.environ.get("FAKE_SYFT_FAIL"):
            sys.stderr.write("[0000] ERROR could not fetch image: UNAUTHORIZED: authentication required\\n"); sys.exit(1)
        out = next(a.split("=", 1)[1] for a in args if a.startswith("syft-json="))
        open(out, "w").write(json.dumps({"artifacts": [{"name": "php-cli", "version": "8.1.0", "type": "binary"}],
                                         "source": {"metadata": {}}, "src": args[1]}))
        sys.exit(0)
    ''').replace("PYTHON", sys.executable)


def _tools(tmp_path):
    for name in ("grype", "syft"):
        p = tmp_path / name
        p.write_text(FAKE_TOOL)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    doc = tmp_path / "grype.json"
    doc.write_text(json.dumps(GRYPE_DOC))
    return {"vuln_grype_path": str(tmp_path / "grype"), "vuln_syft_path": str(tmp_path / "syft"),
            "vuln_tool_env": f"FAKE_GRYPE_DOC={doc}", "data_dir": str(tmp_path / "data")}


async def _reset():
    pool = db.pool()
    await pool.execute("TRUNCATE alerts, vuln_images, vuln_findings, vuln_cache, vuln_closed, unraid_servers")
    await pool.execute("DELETE FROM kv WHERE key LIKE 'vulnscan:%'")
    await pool.execute("DELETE FROM snapshots WHERE key LIKE 'unraid:%'")


@needs_db
def test_scan_cycle_alerts_and_closes(tmp_path):
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            s = Settings(vuln_scan_enabled=True, vuln_alerts=True, vuln_sources=ALL_OFF, vuln_app_checks="",
                         vuln_images="registry.example/team/app@sha256:abc", **_tools(tmp_path))
            sc = VulnScanner(s)
            await sc.cycle()
            st = await db.kv_get("vulnscan:status")
            assert st["tools"]["grype"]["ok"] and st["db"]["valid"] and st["db"]["age_days"] < 1 and not st.get("error")
            img = await pool.fetchrow("SELECT * FROM vuln_images")
            assert img["status"] == "ok" and img["packages"] == 1 and img["sbom_source"] == "registry (exact digest)"
            assert img["version"]["version"] is None and img["version"]["tried"]  # nothing in this image says its version
            assert (tmp_path / "data" / "vulnscan" / "sbom").is_dir()
            rows = {r["vuln"]: r for r in await pool.fetch("SELECT * FROM vuln_findings")}
            assert rows["CVE-2024-4577"]["alerted"] and rows["GHSA-aaaa-bbbb-cccc"]["alerted"]
            assert not rows["CVE-2023-0001"]["alerted"] and rows["CVE-2023-0001"]["why"] == "no fixed version yet"
            a = await pool.fetchrow("SELECT * FROM alerts WHERE rule = 'container_vulnerable'")
            assert a["status"] == "open" and a["severity"] == "critical" and a["count"] == 2
            assert "actively exploited" in a["title"] and "CVE-2024-4577" in a["description"]
            assert a["fingerprint"] == "vuln:registry.example/team/app"
            # second run: the stored SBOM is matched again, not read again; first_seen is kept
            first = rows["CVE-2024-4577"]["first_seen"]
            sbom_at = img["sbom_at"]
            await sc.cycle()
            assert await pool.fetchval("SELECT sbom_at FROM vuln_images") == sbom_at
            assert await pool.fetchval("SELECT first_seen FROM vuln_findings WHERE vuln = 'CVE-2024-4577'") == first
            # exceptions: the alert closes by itself
            s.vuln_ignore = "CVE-2024-4577\nCVE-2023-0002 on */app"
            await sc.evaluate()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'container_vulnerable'") == "closed"
            assert await pool.fetchval("SELECT ignored FROM vuln_findings WHERE vuln = 'CVE-2024-4577'") == "CVE-2024-4577"
            assert not await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'vuln_scan_problem'")
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_problems_are_reported_and_close_again(tmp_path):
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            tools = _tools(tmp_path)
            # scanner missing: one clear alert, nothing else is tried
            s = Settings(vuln_scan_enabled=True, vuln_alerts=True, vuln_sources=ALL_OFF, vuln_app_checks="",
                         vuln_images="registry.example/team/app:1", **{**tools, "vuln_syft_path": "/nonexistent/syft"})
            sc = VulnScanner(s)
            await sc.cycle()
            st = await db.kv_get("vulnscan:status")
            assert not st["tools"]["syft"]["ok"] and "was not found" in st["tools"]["syft"]["error"]
            a = await pool.fetchrow("SELECT * FROM alerts WHERE rule = 'vuln_scan_problem'")
            assert a["severity"] == "medium" and "can't run" in a["title"] and "/nonexistent/syft" in a["description"]
            assert not await pool.fetchval("SELECT count(*) FROM vuln_images")
            # fixed: the alert closes; an outdated database that can't be updated is reported instead
            s.vuln_syft_path = tools["vuln_syft_path"]
            s.vuln_tool_env = tools["vuln_tool_env"] + "\nFAKE_DB_FAIL=1\nFAKE_DB_BUILT=2026-01-01T00:00:00Z"
            await sc.cycle()
            assert await pool.fetchval("SELECT status FROM alerts WHERE fingerprint = 'vulnscan:tools'") == "closed"
            db_alert = await pool.fetchrow("SELECT * FROM alerts WHERE fingerprint = 'vulnscan:db'")
            assert db_alert["status"] == "open" and "Forbidden" in db_alert["description"]
            st = await db.kv_get("vulnscan:status")
            assert st["db"]["update_ok"] is False and st["db"]["age_days"] > 30
            # an image that can't be read: the error is stored; the second failure in a row alerts
            s.vuln_tool_env = tools["vuln_tool_env"] + "\nFAKE_SYFT_FAIL=1"
            s.vuln_images = "registry.example/team/other:2"
            await sc.cycle()
            row = await pool.fetchrow("SELECT * FROM vuln_images WHERE image = 'registry.example/team/other:2'")
            assert row["status"] == "error" and "UNAUTHORIZED" in row["error"] and row["errors"] == 1
            assert "registry (current image of the tag)" in row["error"]
            assert not await pool.fetchval("SELECT count(*) FROM alerts WHERE fingerprint LIKE 'vulnscan:image:%'")
            await sc.cycle()
            a = await pool.fetchrow("SELECT * FROM alerts WHERE fingerprint LIKE 'vulnscan:image:%'")
            assert a["status"] == "open" and a["severity"] == "low" and "other:2" in a["title"]
            assert await pool.fetchval("SELECT status FROM alerts WHERE fingerprint = 'vulnscan:db'") == "closed"
            s.vuln_tool_env = tools["vuln_tool_env"]
            await sc.cycle()
            assert await pool.fetchval("SELECT status FROM alerts WHERE fingerprint LIKE 'vulnscan:image:%'") == "closed"
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_sources_fall_back_and_report(tmp_path):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if req.url.host == "moved.example":
            return httpx.Response(404)
        if req.url.host == "html.example":
            return httpx.Response(200, text="<html>maintenance</html>")
        if req.url.host == "kev.example":
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": f"CVE-2024-{i:04d}"} for i in range(20)]})
        if req.url.host == "epss.example":
            ids = req.url.params["cve"].split(",")
            return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in ids]})
        return httpx.Response(500)

    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            s = Settings(**_tools(tmp_path))
            sc = VulnScanner(s)
            await sc.load_status()
            srcs = parse_sources("kev: https://moved.example/kev.json | json vulnerabilities[].cveID\n"
                                 "kev: https://html.example/kev.json | json vulnerabilities[].cveID\n"
                                 "kev: https://kev.example/kev.json | json vulnerabilities[].cveID\n"
                                 "epss: https://epss.example/q?cve={cves}")
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                await sc.refresh_kev(client, srcs["kev"])
                st = (await db.kv_get("vulnscan:status"))["sources"]["kev"]
                assert st["ok"] and st["count"] == 20 and st["url"] == "https://kev.example/kev.json"
                assert len(await db.kv_get("vulnscan:kev")) == 20 and len(calls) == 3
                # all down: kept list, error per line, alert only after the grace time
                await sc.refresh_kev(client, srcs["kev"][:2], force=True)
                st = (await db.kv_get("vulnscan:status"))["sources"]["kev"]
                assert not st["ok"] and "line 1 moved.example/kev.json: HTTP 404" in st["error"]
                assert "line 2 html.example/kev.json: the answer is not JSON" in st["error"]
                assert len(await db.kv_get("vulnscan:kev")) == 20
                assert not await db.pool().fetchval("SELECT count(*) FROM alerts")
                sc.status["sources"]["kev"]["failing_since"] -= 3 * 86400
                await sc.refresh_kev(client, srcs["kev"][:2], force=True)
                a = await db.pool().fetchrow("SELECT * FROM alerts WHERE fingerprint = 'vulnscan:source:kev'")
                assert a["severity"] == "low" and "HTTP 404" in a["description"]
                await sc.refresh_kev(client, srcs["kev"], force=True)
                assert await db.pool().fetchval("SELECT status FROM alerts WHERE fingerprint = 'vulnscan:source:kev'") == "closed"
                # EPSS: 100 CVEs per request, cached
                cves = {f"CVE-2024-{i:04d}" for i in range(150)}
                await sc.enrich_epss(client, srcs["epss"], cves)
                assert sum("epss.example" in c for c in calls) == 2
                assert await db.pool().fetchval("SELECT count(*) FROM vuln_cache WHERE kind = 'epss'") == 150
                await sc.enrich_epss(client, srcs["epss"], cves)
                assert sum("epss.example" in c for c in calls) == 2
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_inventory_reads_unraid_and_docker_api(tmp_path):
    def docker(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/containers/json":
            return httpx.Response(200, json=[{"Names": ["/nextcloud"], "Image": "nextcloud:30", "ImageID": "sha256:img1"},
                                             {"Names": ["/db"], "Image": "mariadb:11", "ImageID": "sha256:img2"}])
        if req.url.path == "/images/sha256:img1/json":
            return httpx.Response(200, json={"RepoDigests": ["nextcloud@sha256:d1"],
                                             "Config": {"Env": ["NEXTCLOUD_VERSION=30.0.1"], "Labels": {"a": "b"}}})
        return httpx.Response(403, text="Forbidden")

    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key, docker_url) VALUES "
                                      "('Tower', 'http://tower', 'k', 'http://tower:2375') RETURNING id")
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/nextcloud"], "image": "nextcloud:30", "state": "RUNNING"},
                                                           {"names": ["/web"], "image": "nginx:1", "state": "RUNNING"},
                                                           {"names": ["/skipme"], "image": "skip/me", "state": "RUNNING"}])
            sc = VulnScanner(Settings(vuln_exclude="skip*", vuln_images="postgres:18", **_tools(tmp_path)))
            await sc.load_status()
            real = httpx.AsyncClient

            class Mocked(real):
                def __init__(self, *a, **kw):
                    kw["transport"] = httpx.MockTransport(docker)
                    super().__init__(*a, **kw)
            import lookingglass.vulnscan as vs
            vs.httpx.AsyncClient = Mocked
            try:
                targets = {t.image: t for t in await sc.inventory()}
            finally:
                vs.httpx.AsyncClient = real
            assert set(targets) == {"nextcloud:30", "nginx:1", "postgres:18"}
            nc = targets["nextcloud:30"]
            assert nc.digest == "sha256:d1" and nc.env["NEXTCLOUD_VERSION"] == "30.0.1" and nc.containers[0]["server"] == "Tower"
            assert [x[0] for x in sc.syft_sources(nc)] == ["registry (exact digest)", "Docker API export"]
            assert sc.syft_sources(nc)[1][2]["DOCKER_HOST"] == "tcp://tower:2375"
            assert targets["nginx:1"].notes and targets["nginx:1"].digest is None
            st = (await db.kv_get("vulnscan:status"))["inventory"][str(sid)]
            assert st["ok"] and st["docker_api"] == "ok" and st["containers"] == 2
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_docker_api_refusal_names_the_missing_variable(tmp_path):
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key, docker_url) VALUES "
                                      "('Tower', 'http://tower', 'k', 'http://tower:2375') RETURNING id")
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/app"], "image": "app:1"}])

            def proxy(req):  # CONTAINERS=1 but no IMAGES=1
                if req.url.path == "/containers/json":
                    return httpx.Response(200, json=[{"Names": ["/app"], "Image": "app:1", "ImageID": "sha256:x"}])
                return httpx.Response(403)
            import lookingglass.vulnscan as vs
            real = httpx.AsyncClient

            class Mocked(real):
                def __init__(self, *a, **kw):
                    kw["transport"] = httpx.MockTransport(proxy)
                    super().__init__(*a, **kw)
            vs.httpx.AsyncClient = Mocked
            try:
                sc = VulnScanner(Settings(**_tools(tmp_path)))
                await sc.load_status()
                targets = await sc.inventory()
            finally:
                vs.httpx.AsyncClient = real
            st = (await db.kv_get("vulnscan:status"))["inventory"][str(sid)]
            assert "IMAGES=1" in st["docker_api"] and "Docker tab" in st["docker_api"]
            assert targets[0].digest is None and targets[0].notes  # still scanned, by tag
        finally:
            await db.close()

    asyncio.run(main())


def _dotnet(name, inst, searched, fix="10.0.114-10.0.14-0ubuntu1~26.04.1"):
    return {"vulnerability": {"id": "CVE-2026-111497", "dataSource": "https://ubuntu.com/security/CVE-2026-111497",
                              "urls": ["https://www.cve.org/CVERecord?id=CVE-2026-111497"], "severity": "Critical",
                              "cvss": [{"source": "nvd@nist.gov", "version": "3.1", "metrics": {"baseScore": 9.8}}],
                              "fix": {"versions": [fix], "state": "fixed"}},
            "matchDetails": [{"type": "exact-indirect-match", "matcher": "dpkg-matcher",
                              "searchedBy": {"distro": {"type": "ubuntu", "version": "26.04"}, "namespace": "ubuntu:distro:ubuntu:26.04",
                                             "package": {"name": "dotnet10", "version": searched}},
                              "found": {"vulnerabilityID": "CVE-2026-111497", "versionConstraint": f"< {fix} (deb)"}}],
            "artifact": {"name": name, "version": inst, "type": "deb", "upstreams": [{"name": "dotnet10"}],
                         "locations": [{"path": f"/usr/share/doc/{name}/copyright"},
                                       {"path": "/var/lib/dpkg/status", "annotations": {"evidence": "primary"}}]}}


def test_debian_versions():
    from lookingglass.vulnscan import dpkg_compare
    assert dpkg_compare("10.0.13-0ubuntu1~26.04.1", "10.0.14-0ubuntu1~26.04.1") == -1
    assert dpkg_compare("1.0~rc1-1", "1.0-1") == -1 and dpkg_compare("1:1.0-1", "2.0-1") == 1
    assert dpkg_compare("2.36-9+deb12u10", "2.36-9+deb12u7") == 1 and dpkg_compare("1.2.3", "1.2.3") == 0


def test_one_cve_of_a_source_package_is_one_finding_with_how_it_was_matched():
    from lookingglass.vulnscan import group_findings
    inst = "10.0.13-0ubuntu1~26.04.1"
    src = "10.0.113-10.0.13-0ubuntu1~26.04.1"  # Grype knew the source version: formats match, a real finding
    fs = parse_grype({"matches": [_dotnet(n, inst, src) for n in ("dotnet-host-10.0", "aspnetcore-runtime-10.0", "dotnet-hostfxr-10.0")]})
    assert len(fs) == 3 and all(f["upstream"] == "dotnet10" for f in fs)
    f = fs[0]
    assert f["locations"][0] == "/var/lib/dpkg/status" and f["url"].startswith("https://ubuntu.com/security/")
    assert f["matched"]["searched"] == f"dotnet10 {src}" and f["matched"]["constraint"].startswith("< 10.0.114")
    assert f["matched"]["distro"] == "ubuntu 26.04" and "note" not in f["matched"]
    g = group_findings([{**x, "image_key": "img"} for x in fs])
    assert len(g) == 1 and g[0]["group"] == "dotnet10" and [p["name"] for p in g[0]["packages"]] == \
        ["aspnetcore-runtime-10.0", "dotnet-host-10.0", "dotnet-hostfxr-10.0"]
    assert len(group_findings([{**fs[0], "image_key": "a"}, {**fs[1], "image_key": "b"}])) == 2  # per image
    # an exception for the source package covers all of them
    pol = Policy(7.0, True, None, True, parse_ignore("pkg:dotnet10"))
    assert all(pol.judge(x, ["fileflows"])[1] for x in fs)


def test_binary_version_compared_with_a_source_version():
    fixed = parse_grype({"matches": [_dotnet("dotnet-host-10.0", "10.0.14-0ubuntu1~26.04.1", "10.0.14-0ubuntu1~26.04.1")]})[0]
    assert fixed["matched"]["probably_fixed"] and "already fixed" in fixed["matched"]["note"]
    pol = Policy(7.0, True, None, True, [])
    alert, _, why = pol.judge({**fixed, "kev": True}, ["x"])
    assert not alert and "already fixed" in why  # also when actively exploited: the package has the fix
    old = parse_grype({"matches": [_dotnet("dotnet-host-10.0", "10.0.13-0ubuntu1~26.04.1", "10.0.13-0ubuntu1~26.04.1")]})[0]
    assert old["matched"]["probably_fixed"] is False and "not fixed yet" in old["matched"]["note"]
    assert pol.judge(old, ["x"])[0]


def test_group_marks_packages_that_already_have_the_fix():
    from lookingglass.vulnscan import group_findings
    done = parse_grype({"matches": [_dotnet("dotnet-runtime-10.0", "10.0.14-0ubuntu1~26.04.1", "10.0.14-0ubuntu1~26.04.1")]})[0]
    todo = parse_grype({"matches": [_dotnet("dotnet-host-10.0", "10.0.13-0ubuntu1~26.04.1", "10.0.13-0ubuntu1~26.04.1")]})[0]
    g = group_findings([{**done, "image_key": "i"}, {**todo, "image_key": "i"}])[0]
    assert {p["name"]: p["fixed"] for p in g["packages"]} == {"dotnet-runtime-10.0": True, "dotnet-host-10.0": False}
    assert g["package"] == "dotnet-host-10.0" and not g["matched"]["probably_fixed"]  # the row describes the unfixed one


def test_version_of_every_image():
    from lookingglass.vulnscan import detect_version, parse_version_sources
    rules = parse_version_sources(Settings().vuln_version_sources)
    fileflows = parse_image("revenz/fileflows:stable")
    # inherited Ubuntu label skipped, the app's own environment variable used
    d = detect_version({"labels": {"org.opencontainers.image.version": "26.04"}, "env": {"FILEFLOWS_VERSION": "25.11.3.6000"},
                        "tag": "stable", "os_version": "26.04"}, fileflows, rules)
    assert d["version"] == "25.11.3.6000" and d["from"] == "environment variable FILEFLOWS_VERSION"
    ls = detect_version({"labels": {"build_version": "Linuxserver.io version:- 10.10.3-ls45 Build-date:- 2026-10-01"}},
                        parse_image("lscr.io/linuxserver/jellyfin:latest"), rules)
    assert ls["version"] == "10.10.3" and "build_version" in ls["from"]
    assert detect_version({"tag": "1.22.3"}, parse_image("gitea/gitea:1.22.3"), rules)["version"] == "1.22.3"
    none = detect_version({"tag": "latest"}, parse_image("x/y:latest"), rules)
    assert none["version"] is None and "image tag" in none["tried"]
    with pytest.raises(ValueError, match="line 1"):
        parse_version_sources("foo bar")
    with pytest.raises(app_config.SettingsError, match="Where image versions are read"):
        app_config._coerce(app_config.BY_KEY["vuln_version_sources"], "label")


@needs_db
def test_alert_closes_right_after_an_update(tmp_path):
    """Container updated to an image without the findings: the old image is dropped in the same check and the alert
    closes - unless its server could not be listed (then the old results stay for 2 days)."""
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            tools = _tools(tmp_path)
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key) VALUES ('Tower', 'http://t', 'k') RETURNING id")
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/app"], "image": "team/app:1", "state": "RUNNING"}])
            s = Settings(vuln_scan_enabled=True, vuln_alerts=True, vuln_sources=ALL_OFF, vuln_app_checks="", **tools)
            sc = VulnScanner(s)
            await sc.cycle()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'container_vulnerable'") == "open"
            # updated: same repo, new tag; the new image has no findings
            (tmp_path / "clean.json").write_text(json.dumps({"matches": []}))
            s.vuln_tool_env = f"FAKE_GRYPE_DOC={tmp_path / 'clean.json'}"
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/app"], "image": "team/app:2", "state": "RUNNING"}])
            await sc.cycle()
            assert [r["image"] for r in await pool.fetch("SELECT image FROM vuln_images")] == ["team/app:2"]
            a = await pool.fetchrow("SELECT status, description FROM alerts WHERE rule = 'container_vulnerable'")
            assert a["status"] == "closed" and "Closed automatically" in a["description"]
            # a server whose containers could not be listed keeps its images
            await pool.execute("DELETE FROM snapshots WHERE key = $1", f"unraid:{sid}:docker")
            await sc.cycle()
            assert await pool.fetchval("SELECT count(*) FROM vuln_images") == 1
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_an_updated_container_is_checked_right_away(tmp_path):
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key) VALUES ('Tower', 'http://t', 'k') RETURNING id")
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/app"], "image": "team/app:latest", "created": 100}])
            sc = VulnScanner(Settings(vuln_scan_enabled=True, vuln_alerts=True, vuln_sources=ALL_OFF, vuln_app_checks="", **_tools(tmp_path)))
            await sc.load_status()
            runs = []

            async def cycle(rebuild=False):
                runs.append(rebuild)
                await sc.save_status(last_try=time.time())
            sc.cycle = cycle
            await sc.tick()
            assert len(runs) == 1  # first time
            sc.status["last_try"] -= 700
            await sc.tick()
            assert len(runs) == 1  # nothing changed, not due
            await db.set_snapshot(f"unraid:{sid}:docker", [{"names": ["/app"], "image": "team/app:latest", "created": 200}])
            sc.status["last_try"] -= 700
            await sc.tick()
            assert len(runs) == 2  # recreated by an update: checked now
        finally:
            await db.close()

    asyncio.run(main())


# ------------------------------------------------ distribution suffixes ---
def _pkg_match(version, constraint, fixes, pkg_type="python", name="pybot", vid="CVE-2026-1111"):
    return {"vulnerability": {"id": vid, "severity": "High", "fix": {"versions": fixes, "state": "fixed" if fixes else "unknown"},
                              "cvss": [{"source": "nvd@nist.gov", "version": "3.1", "metrics": {"baseScore": 8.1}}]},
            "matchDetails": [{"type": "cpe-match", "matcher": "python-matcher",
                              "searchedBy": {"package": {"name": name, "version": version}},
                              "found": {"versionConstraint": constraint}}],
            "artifact": {"name": name, "version": version, "type": pkg_type}}


def test_version_suffixes():
    from lookingglass.vulnscan import plain_affected, split_suffix
    assert split_suffix("1.3.1+ubuntu26") == ("1.3.1", "+ubuntu26")
    assert split_suffix("2:1.3.1-0ubuntu1~26.04.1") == ("1.3.1", "-0ubuntu1~26.04.1")
    assert split_suffix("1.3.1-r2") == ("1.3.1", "-r2") and split_suffix("1.3.1+b1") == ("1.3.1", "+b1")
    for v in ("1.3.1", "1.3.1-rc1", "1.3.1~beta2", "1.3.1.dev3", "1.3.1-alpha", "latest"):
        assert split_suffix(v) is None, v  # nothing to strip, or a real pre-release
    assert plain_affected("< 1.3.1 (python)", "1.3.1") is False and plain_affected("< 1.3.1", "1.3.0") is True
    assert plain_affected(">= 2.0, < 2.3.4 || < 1.9 (semver)", "1.9") is False
    assert plain_affected(">= 2.0, < 2.3.4 || < 1.9 (semver)", "2.3") is True
    assert plain_affected("<= 1.3.1", "1.3.1") is True and plain_affected("< 1.3.1-2 (deb)", "1.3.1") is None
    assert plain_affected("none (unknown)", "1.0") is None and plain_affected("", "1.0") is None


def test_distribution_suffix_is_not_an_earlier_version():
    """pybot 1.3.1+ubuntu26 against 'fixed in 1.3.1': the suffix is the distribution's, not a pre-release."""
    pol = Policy(7.0, True, None, True, [])
    f = parse_grype({"matches": [_pkg_match("1.3.1+ubuntu26", "< 1.3.1 (python)", ["1.3.1"])]})[0]
    assert f["matched"]["probably_fixed"] and "1.3.1+ubuntu26 is release 1.3.1" in f["matched"]["note"]
    alert, _, why = pol.judge(f, ["x"])
    assert not alert and why.startswith("not affected")
    # same with only a fixed version known (no usable constraint), and with a Debian-style revision
    f = parse_grype({"matches": [_pkg_match("1.3.1-0ubuntu1", "", ["1.3.1"])]})[0]
    assert f["matched"]["probably_fixed"]
    # the fixed version of the same line counts, not a later line's
    f = parse_grype({"matches": [_pkg_match("1.2.9+deb12u1", "", ["1.2.9", "1.3.1"])]})[0]
    assert f["matched"]["probably_fixed"]
    # really older, a real pre-release, or a fix with its own distribution revision: Grype's verdict stands
    for v, c, fx in [("1.3.0+ubuntu26", "< 1.3.1 (python)", ["1.3.1"]), ("1.3.1-rc1", "< 1.3.1", ["1.3.1"]),
                     ("1.3.1+ubuntu26", "", ["1.3.1-2ubuntu3"]), ("1.3.1+ubuntu26", "<= 1.3.1", ["1.3.2"])]:
        f = parse_grype({"matches": [_pkg_match(v, c, fx)]})[0]
        assert "probably_fixed" not in f["matched"], (v, c, fx)
        assert pol.judge(f, ["x"])[0], (v, c, fx)


def test_alert_and_show_scores():
    """Two separate scores: one for an alert, one for being listed on the page."""
    crit = {"vuln": "CVE-1", "cvss": 9.8, "kev": False, "fix_versions": ["2"]}
    mid = {"vuln": "CVE-2", "cvss": 5.0, "kev": False, "fix_versions": ["2"]}
    nosc = {"vuln": "CVE-3", "cvss": None, "severity": "Unknown", "kev": False, "fix_versions": ["2"]}
    assert Settings().vuln_alerts is False and not Policy.of(Settings()).alerts  # alerts off by default
    pol = Policy.of(Settings(vuln_min_cvss="9.0", vuln_show_min_cvss="4"))
    assert pol.judge(crit, ["x"])[0] and not pol.judge(mid, ["x"])[0]  # alert score 9
    assert pol.shown(mid, False) and not pol.shown({**mid, "cvss": 3.9}, False) and not pol.shown(nosc, False)
    assert not pol.shown({**mid, "cvss": 1.0}, True)  # your page settings win, also when it would alert
    every = Policy.of(Settings())
    assert every.show_min == 0 and every.shown(nosc, False)  # default: everything is listed
    assert Policy.of(Settings(vuln_show_min_cvss="nonsense")).show_min == 0
    with pytest.raises(app_config.SettingsError, match="Minimum CVSS score to show"):
        app_config._coerce(app_config.BY_KEY["vuln_show_min_cvss"], "11")
    assert "vuln_alert_min_level" not in app_config.BY_KEY


def test_vulnerability_settings_are_grouped():
    fs = [f for f in app_config.FIELDS if f.group == "vulns"]
    assert all(f.section in app_config.SECTIONS for f in fs)
    seen, last = [], None
    for f in fs:  # every section in one block, not spread over the tab
        if f.section != last:
            assert f.section not in seen, f.section
            seen.append(f.section)
            last = f.section
    alerts = [f.key for f in fs if f.section == "Alerts"]
    assert alerts == ["vuln_alerts", "vuln_min_cvss", "vuln_kev_always", "vuln_epss_min", "vuln_only_fixed"]
    assert [f.key for f in fs if f.section == "Vulnerabilities page"] == [
        "vuln_show_min_cvss", "vuln_hide_wont_fix", "vuln_hide_no_fix", "vuln_hide_not_affected", "vuln_hide_cpe",
        "vuln_hide_types"]
    view = app_config.public_view(Settings())
    assert view["sections"]["Alerts"] and next(x for x in view["fields"] if x["key"] == "vuln_min_cvss")["section"] == "Alerts"


def _Req():  # stands in for the request the login guard marked
    from types import SimpleNamespace
    return SimpleNamespace(state=SimpleNamespace(user={"username": "admin"}))


@needs_db
def test_closed_findings_stay_away(tmp_path):
    """Closing a finding hides it on the page and from the alert; it stays closed after a new scan, reopening brings
    it back. Alerts can be switched off or limited to a level."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            s = Settings(vuln_scan_enabled=True, vuln_alerts=True, vuln_sources=ALL_OFF, vuln_app_checks="",
                         vuln_images="registry.example/team/app@sha256:abc", **_tools(tmp_path))
            sc = VulnScanner(s)
            await sc.cycle()
            app = create_app(s, None)
            ep = {r.path: r.endpoint for r in app.routes if getattr(r, "path", "").startswith("/api/vulns")}
            rows = await ep["/api/vulns/findings"](image=None, show="all", q=None, limit=1000)
            php = next(r for r in rows if r["vuln"] == "CVE-2024-4577")
            assert php["repo"] == "registry.example/team/app" and php["group"] == "php-cli"
            out = await ep["/api/vulns/close"](_Req(), {"items": [{"vuln": php["vuln"], "group": php["group"],
                                                                     "repo": php["repo"]}], "note": "not reachable"})
            assert out["closed"] == 1 and await db.kv_get("vulnscan:reevaluate")
            rows = await ep["/api/vulns/findings"](image=None, show="all", q=None, limit=1000)
            assert "CVE-2024-4577" not in {r["vuln"] for r in rows}
            closed = await ep["/api/vulns/findings"](image=None, show="closed", q=None, limit=1000)
            assert closed[0]["closed_by"] == "admin" and closed[0]["note"] == "not reachable"
            assert closed[0]["images"] == ["registry.example/team/app@sha256:abc"]
            overview = await ep["/api/vulns"]()
            assert overview["closed_count"] == 1 and overview["images"][0]["kev"] == 0
            await sc.tick()  # picks up the re-evaluation request
            assert not await db.kv_get("vulnscan:reevaluate")
            f = await pool.fetchrow("SELECT alerted, why FROM vuln_findings WHERE vuln = 'CVE-2024-4577'")
            assert not f["alerted"] and f["why"] == "closed by you"
            a = await pool.fetchrow("SELECT status, count, description FROM alerts WHERE rule = 'container_vulnerable'")
            assert a["status"] == "open" and "CVE-2024-4577" not in a["description"].split("\n\n")[1]
            # a new scan does not bring it back
            await sc.cycle(rebuild=True)
            assert await pool.fetchval("SELECT why FROM vuln_findings WHERE vuln = 'CVE-2024-4577'") == "closed by you"
            # closing the other one (by its alias, for every image) closes the alert
            await ep["/api/vulns/close"](_Req(), {"items": [{"vuln": "CVE-2023-0002", "group": "guzzlehttp/guzzle"}],
                                                  "scope": "all"})
            await sc.evaluate()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'container_vulnerable'") == "closed"
            # reopen: alerted again
            await ep["/api/vulns/reopen"]({"items": [{"vuln": "CVE-2024-4577", "grp": "php-cli",
                                                      "repo": "registry.example/team/app"}]})
            await sc.evaluate()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'container_vulnerable' "
                                       "ORDER BY id DESC LIMIT 1") == "open"
            # show from CVSS 9.9: everything left is hidden (CVE-2023-0002 / GHSA is closed), also CVE-2024-4577 (9.8)
            # which raises an alert - the alert still lists it and says it is hidden on the page
            s.vuln_show_min_cvss = "9.9"
            await sc.evaluate()
            rows = await ep["/api/vulns/findings"](image=None, show="all", q=None, limit=1000)
            assert rows == []
            overview = await ep["/api/vulns"]()
            assert overview["hidden_count"] == 2 and overview["policy"]["show_min_cvss"] == "9.9"
            assert overview["hidden"] == {"CVSS below 9.9": 2} and overview["images"][0]["total"] == 0
            desc = await pool.fetchval("SELECT description FROM alerts WHERE rule = 'container_vulnerable' "
                                       "AND status = 'open' ORDER BY id DESC LIMIT 1")
            assert "CVE-2024-4577" in desc and "hidden on the Vulnerabilities page: CVSS below 9.9" in desc
            s.vuln_show_min_cvss = "0"
            await sc.evaluate()
            assert await pool.fetchval("SELECT bool_and(shown) FROM vuln_findings")
            # alerts off closes the alert, the findings stay listed
            s.vuln_alerts = False
            await sc.evaluate()
            assert not await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'container_vulnerable' AND status = 'open'")
            assert await pool.fetchval("SELECT alerted FROM vuln_findings WHERE vuln = 'CVE-2024-4577'")
            with pytest.raises(Exception, match="Select"):
                await ep["/api/vulns/close"](_Req(), {"items": []})
        finally:
            await db.close()

    asyncio.run(main())


def _deb_match(name, inst, constraint, fix):
    return {"vulnerability": {"id": "CVE-2026-2222", "severity": "Medium", "fix": {"versions": [fix], "state": "fixed"},
                              "cvss": [{"source": "nvd@nist.gov", "version": "3.1", "metrics": {"baseScore": 7.5}}]},
            "matchDetails": [{"type": "exact-direct-match", "searchedBy": {"package": {"name": name, "version": inst}},
                              "found": {"versionConstraint": constraint}}],
            "artifact": {"name": name, "version": inst, "type": "deb"}}


def test_distribution_patched_build_is_explained_not_hidden():
    """brotli 1.1.0-2 vs < 1.1.0-2+deb13u1: same release, but the image lacks the distribution's security patch."""
    pol = Policy(7.0, True, None, True, [])
    for inst, fix in [("1.1.0-2", "1.1.0-2+deb13u1"), ("1.1.0-2build2", "1.1.0-2ubuntu0.1")]:
        f = parse_grype({"matches": [_deb_match("brotli", inst, f"< {fix} (deb)", fix)]})[0]
        m = f["matched"]
        assert "probably_fixed" not in m and "patched build" in m["note"] and inst in m["note"], inst
        assert pol.judge(f, ["x"])[0]  # a real finding: it still alerts
    # already the patched build: Grype would not report it, and no note claims otherwise
    from lookingglass.vulnscan import patch_note
    assert patch_note({"pkg_type": "deb", "version": "1.1.0-2+deb13u1", "fix_versions": ["1.1.0-2+deb13u1"]}) is None
    go = parse_grype({"matches": [{"vulnerability": {"id": "GO-2026-1", "fix": {"versions": ["0.52.0"], "state": "fixed"}},
                                   "artifact": {"name": "golang.org/x/crypto", "version": "v0.19.0", "type": "go-module",
                                                "locations": [{"path": "/usr/bin/app"}]}}]})[0]
    assert "Compiled into a Go program (/usr/bin/app)" in go["matched"]["note"] and "probably_fixed" not in go["matched"]


def test_page_settings_hide_findings():
    wont = {"vuln": "CVE-1", "cvss": 5.0, "fix_state": "wont-fix", "fix_versions": [], "pkg_type": "deb"}
    nofix = {"vuln": "CVE-2", "cvss": 5.0, "fix_state": "not-fixed", "fix_versions": [], "pkg_type": "deb"}
    fixed = {"vuln": "CVE-3", "cvss": 5.0, "fix_state": "fixed", "fix_versions": ["2"], "pkg_type": "go-module"}
    na = {**fixed, "pkg_type": "deb", "matched": {"probably_fixed": True}}
    cpe = {**fixed, "pkg_type": "binary", "matched": {"type": "cpe-match"}}
    default = Policy.of(Settings())
    assert default.hidden_by(na) == "not affected"  # on by default
    assert all(default.hidden_by(x) is None for x in (wont, nofix, fixed, cpe))
    pol = Policy.of(Settings(vuln_hide_wont_fix=True, vuln_hide_cpe=True, vuln_hide_types="go-*",
                             vuln_hide_not_affected=False))
    assert pol.hidden_by(wont) == "will not be fixed" and pol.hidden_by(nofix) is None and pol.hidden_by(na) is None
    assert pol.hidden_by(cpe) == "CPE guess" and pol.hidden_by(fixed) == "package type go-module"
    assert Policy.of(Settings(vuln_hide_no_fix=True)).hidden_by(wont) == "no fix yet"
    assert not pol.shown(wont, False) and not pol.shown(wont, True)  # hidden, also when it would alert


def test_hide_packages_by_name_or_type():
    pol = Policy.of(Settings(vuln_hide_types="chromium\nlibx11-*\ngo-module"))
    chromium = {"vuln": "CVE-1", "cvss": 8.8, "package": "chromium", "upstream": "", "pkg_type": "deb", "fix_versions": ["2"]}
    common = {**chromium, "package": "chromium-common", "upstream": "chromium"}  # by its source package
    assert pol.hidden_by(chromium) == "package chromium" and pol.hidden_by(common) == "package chromium"
    assert pol.hidden_by({**chromium, "package": "libx11-6"}) == "package libx11-6"
    assert pol.hidden_by({**chromium, "package": "x", "pkg_type": "go-module"}) == "package type go-module"
    assert pol.hidden_by({**chromium, "package": "chromium-browser-l10n", "upstream": ""}) is None  # no wildcard
    # the reported case: chromium meets the alert rules (CVSS 8.8, fix exists) while alerts are off - still hidden
    assert pol.judge(chromium, ["x"])[0] and not pol.alerts and not pol.shown(chromium, True)


@needs_db
def test_check_now_starts_without_waiting_for_the_start_delay(tmp_path):
    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            s = Settings(vuln_scan_enabled=True, vuln_sources=ALL_OFF, vuln_app_checks="",
                         vuln_images="registry.example/team/app@sha256:abc", **_tools(tmp_path))
            sc = VulnScanner(s)
            await db.kv_set("vulnscan:status", {"last_try": time.time(), "last_scan": time.time() - 7200})
            task = asyncio.create_task(sc.run())
            await db.kv_set("vulnscan:request", {"at": time.time(), "rebuild": False})
            sc.wake.set()  # what the Check now button does
            for _ in range(100):
                st = await db.kv_get("vulnscan:status")
                if st.get("last_scan", 0) > time.time() - 60 and not st.get("running"):
                    break
                await asyncio.sleep(0.1)
            task.cancel()
            assert st["last_scan"] > time.time() - 60, st  # done within seconds, not after the 90 s start delay
            assert not await db.kv_get("vulnscan:request")
        finally:
            await db.close()

    asyncio.run(main())
