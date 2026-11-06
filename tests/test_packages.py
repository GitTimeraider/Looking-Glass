"""Container packages (Unraid › Packages): read with Syft only for new / updated images or when asked, listed and
searchable."""
import asyncio
import os
import stat
import sys
import textwrap

import pytest

from lookingglass import app_config, db
from lookingglass.config import Settings
from lookingglass.packages import (
    PackageReader,
    compact,
    parse_image,
)

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

FAKE_SYFT = textwrap.dedent('''\
    #!PYTHON
    import json, os, sys
    args = sys.argv[1:]
    src = args[1]
    with open(os.environ["SYFT_LOG"], "a") as fh:
        fh.write(src + "\\n")
    if "broken" in src:
        sys.stderr.write("[0000] ERROR could not fetch image: UNAUTHORIZED: authentication required\\n"); sys.exit(1)
    out = next(a.split("=", 1)[1] for a in args if a.startswith("syft-json="))
    php = [{"name": "php", "version": "8.3.1", "type": "binary", "language": "", "locations": [{"path": "/usr/local/bin/php"}]},
           {"name": "guzzlehttp/guzzle", "version": "7.8.0", "type": "php-composer", "language": "php",
            "locations": [{"path": "/var/www/composer.lock"}]}] if "nextcloud" in src else []
    json.dump({"distro": {"prettyName": "Debian GNU/Linux 13 (trixie)"}, "source": {"metadata": {"os": "linux", "architecture": "amd64"}},
               "artifacts": php + [{"name": "openssl", "version": "3.5.1-1", "type": "deb", "locations": [{"path": "/var/lib/dpkg/status"}]}]},
              open(out, "w"))
    ''').replace("PYTHON", sys.executable)


def _syft(tmp_path):
    p = tmp_path / "syft"
    p.write_text(FAKE_SYFT)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "syft.log"
    log.write_text("")
    return {"pkg_syft_path": str(p), "pkg_tool_env": f"SYFT_LOG={log}", "data_dir": str(tmp_path / "data")}, log


def test_compact_list_and_names():
    doc = {"distro": {"name": "Alpine Linux", "versionID": "3.22"}, "source": {"metadata": {"os": "linux", "architecture": "arm64"}},
           "artifacts": [{"name": "busybox", "version": "1.37", "type": "apk", "locations": [{"path": "/lib/apk/db/installed"}] * 2},
                         {"version": "no name: skipped"}]}
    c = compact(doc)
    assert c == {"distro": "Alpine Linux 3.22", "os": "linux", "arch": "arm64", "packages": [
        {"name": "busybox", "version": "1.37", "type": "apk", "language": "", "locations": ["/lib/apk/db/installed"]}]}
    assert parse_image("nextcloud:30").full == "docker.io/library/nextcloud"
    assert parse_image("lscr.io/linuxserver/jellyfin").tag == "latest"


def test_settings():
    f = app_config.BY_KEY
    assert all(f[k].group == "packages" for k in ("pkg_enabled", "pkg_image_source", "pkg_exclude", "pkg_syft_path"))
    assert not [k for k in f if k.startswith("vuln_")]  # the vulnerability scanner's settings are gone
    with pytest.raises(app_config.SettingsError, match="NAME=value"):
        app_config._coerce(f["pkg_tool_env"], "just text")
    with pytest.raises(app_config.SettingsError, match="Extra Syft arguments"):
        app_config._coerce(f["pkg_syft_args"], "--x 'unclosed")
    assert Settings().pkg_enabled is False


async def _reset():
    pool = db.pool()
    await pool.execute("TRUNCATE image_packages, unraid_servers")
    await pool.execute("DELETE FROM kv WHERE key LIKE 'packages:%'")
    await pool.execute("DELETE FROM snapshots WHERE key LIKE 'unraid:%'")


@needs_db
def test_read_only_new_or_updated_images_or_when_asked(tmp_path):
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            await _reset()
            pool = db.pool()
            tools, log = _syft(tmp_path)
            reads = lambda: [x for x in log.read_text().splitlines() if x]
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key) VALUES ('Tower', 'http://t', 'k') RETURNING id")
            ctrs = [{"names": ["/nextcloud"], "image": "nextcloud:30", "state": "RUNNING", "created": 100},
                    {"names": ["/db"], "image": "postgres:18", "state": "RUNNING", "created": 100},
                    {"names": ["/skip"], "image": "test/thing:1", "state": "RUNNING", "created": 100}]
            await db.set_snapshot(f"unraid:{sid}:docker", ctrs)
            s = Settings(pkg_enabled=True, pkg_exclude="test/*", **tools)
            r = PackageReader(s)
            await r.tick()  # first time: every image (they are new)
            assert sorted(reads()) == ["registry:docker.io/library/nextcloud:30", "registry:docker.io/library/postgres:18"]
            rows = {x["image"]: x for x in await pool.fetch("SELECT * FROM image_packages")}
            assert set(rows) == {"nextcloud:30", "postgres:18"}  # excluded one left out
            assert rows["nextcloud:30"]["status"] == "ok" and rows["nextcloud:30"]["packages"] == 3
            assert rows["nextcloud:30"]["distro"] == "Debian GNU/Linux 13 (trixie)"
            await r.tick()  # nothing changed: nothing read
            assert len(reads()) == 2
            # nextcloud updated (Unraid recreates the container, digest unknown): only that image is read again
            ctrs[0] = {**ctrs[0], "created": 200}
            await db.set_snapshot(f"unraid:{sid}:docker", ctrs)
            await r.tick()
            assert reads()[2:] == ["registry:docker.io/library/nextcloud:30"]
            # asked for one image / for all
            ep = {x.path: x.endpoint for x in create_app(s, None).routes if getattr(x, "path", "").startswith("/api/packages")}
            await ep["/api/packages/update"]({"image": rows["postgres:18"]["key"]})
            await r.tick()
            assert reads()[3:] == ["registry:docker.io/library/postgres:18"]
            await ep["/api/packages/update"]({})
            await r.tick()
            assert sorted(reads()[4:]) == ["registry:docker.io/library/nextcloud:30", "registry:docker.io/library/postgres:18"]
            # a container removed: its image goes; a failing image is shown with its error
            await db.set_snapshot(f"unraid:{sid}:docker", [ctrs[0], {"names": ["/b"], "image": "broken/x:1", "created": 1}])
            await r.tick()
            rows = {x["image"]: x for x in await pool.fetch("SELECT * FROM image_packages")}
            assert set(rows) == {"nextcloud:30", "broken/x:1"} and "UNAUTHORIZED" in rows["broken/x:1"]["error"]
            # the page
            imgs = await ep["/api/packages/images"]()
            assert imgs["enabled"] and imgs["status"]["last_run"] and len(imgs["images"]) == 2
            call = lambda **kw: ep["/api/packages"](**{"q": None, "type": None, "language": None, "image": None, "limit": 1000, **kw})
            php = await call(q="php")
            assert {x["name"] for x in php["rows"]} == {"php", "guzzlehttp/guzzle"} and php["rows"][0]["containers"] == ["nextcloud"]
            assert (await call(type="php-composer"))["total"] == 1 and (await call(language="php"))["total"] == 1
            assert (await call(q="openssl nextcloud"))["total"] == 1  # every word
            assert (await call(q="php", limit=1))["total"] == 2 and len((await call(q="php", limit=1))["rows"]) == 1
            # switched off: nothing is read, and Update says why
            s.pkg_enabled = False
            with pytest.raises(Exception, match="Switch it on"):
                await ep["/api/packages/update"]({})
        finally:
            await db.close()

    asyncio.run(main())
