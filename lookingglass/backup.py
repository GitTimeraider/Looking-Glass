"""Backup and restore: the database and the encryption key in one file (Settings › Data & detection › Backup).

A backup is a .tar.gz with
    manifest.json        format, version, time, kind, per table its columns and rows
    lookingglass.key     the encryption key: without it the stored credentials in the backup cannot be read
    tables/<name>.csv    every table, as PostgreSQL COPY ... CSV
    README.txt           how to restore
It does not need pg_dump (so it works with any PostgreSQL version Looking Glass supports) and restores into the
current schema: columns added by a newer version get their defaults.

Kinds: "full" = everything; "config" = everything except the collected history that is large and comes back by
itself (events, metrics, dashboard counts, hourly baselines, threat feeds) - settings, accounts, devices, alerts,
filters, rules, reports and learned profiles are in it.

Restore (CLI, see cli.py): replaces the tables that are in the backup, puts the backup's key in place (the current
one is kept next to it) and re-encrypts the saved database connection with it.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import secrets
import shutil
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, crypto, db

log = logging.getLogger(__name__)

FORMAT = 1
KINDS = ("full", "config")
# left out of a "config" backup: large, and collected again by itself
HISTORY = {"events", "event_rollup", "event_rollup_state", "metrics", "period_results", "device_hourly", "hourly_stats",
           "seen_domains", "intel_indicators"}
# tables whose rows depend on others: restored after them (webauthn_credentials -> users)
LATE = ("webauthn_credentials",)

README = """Looking Glass backup
====================

This file holds the Looking Glass database AND its encryption key (lookingglass.key). Anyone who has it can read
every stored credential (API keys, passwords) - keep it as safe as the passwords themselves.

Restore (shell on the Docker host, in the folder with docker-compose.yml):

  1. Copy this file into the data folder:           cp looking-glass-backup-*.tar.gz ./data/
  2. Stop Looking Glass (the database keeps running): docker compose stop looking-glass
  3. Restore:  docker compose run --rm looking-glass python -m lookingglass.cli restore /data/<this file name>
  4. Start it again:                                docker compose start looking-glass

On a new machine: install Looking Glass as usual and finish the setup wizard first (it creates the database
connection), then follow the steps above. Your old accounts, settings and data replace the new ones.
"""


def tmp_root() -> Path:
    root = Path(tempfile.gettempdir()) / "lookingglass-backups"
    root.mkdir(mode=0o700, exist_ok=True)
    return root


async def tables(conn) -> dict[str, list[str]]:
    """Every table of the schema with its columns (in order)."""
    rows = await conn.fetch(
        "SELECT c.table_name, array_agg(c.column_name::text ORDER BY c.ordinal_position) cols "
        "FROM information_schema.columns c JOIN information_schema.tables t "
        "ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
        "WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' GROUP BY 1 ORDER BY 1")
    return {r["table_name"]: list(r["cols"]) for r in rows}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


async def create(data_dir: str, kind: str = "full", progress: dict[str, Any] | None = None) -> Path:
    """Write a backup file into a private temp folder; returns its path."""
    if kind not in KINDS:
        raise ValueError("unknown backup kind")
    progress = progress if progress is not None else {}
    work = Path(tempfile.mkdtemp(prefix="build-", dir=tmp_root()))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = tmp_root() / f"looking-glass-backup-{kind}-{stamp}-{secrets.token_hex(3)}.tar.gz"
    try:
        manifest: dict[str, Any] = {"format": FORMAT, "app": "looking-glass", "version": __version__,
                                    "created": datetime.now(timezone.utc).isoformat(), "kind": kind, "tables": {}}
        async with db.pool().acquire() as conn:
            async with conn.transaction(isolation="repeatable_read", readonly=True):  # one consistent snapshot
                found = await tables(conn)
                wanted = [t for t in found if kind == "full" or t not in HISTORY]
                for i, t in enumerate(wanted):
                    progress.update(step=f"table {t}", done=i, total=len(wanted))
                    path = work / f"{t}.csv"
                    await conn.copy_from_table(t, output=str(path), columns=found[t], format="csv")
                    rows = await conn.fetchval(f"SELECT count(*) FROM {_q(t)}")
                    manifest["tables"][t] = {"columns": found[t], "rows": rows}
        key = crypto.key_path(data_dir)
        if not key.exists():
            raise FileNotFoundError(f"the encryption key {key} is missing")
        progress.update(step="compressing", done=len(manifest["tables"]))

        def pack() -> None:
            with tarfile.open(out, "w:gz", compresslevel=6) as tar:
                def text(name: str, body: str) -> None:
                    data = body.encode()
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
                    tar.addfile(info, io.BytesIO(data))
                text("manifest.json", json.dumps(manifest, indent=1))
                text("README.txt", README)
                tar.add(key, arcname="lookingglass.key")
                for t in manifest["tables"]:
                    tar.add(work / f"{t}.csv", arcname=f"tables/{t}.csv")
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        await asyncio.to_thread(pack)
        progress.update(step="ready", size=out.stat().st_size)
        return out
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cleanup(max_age: float = 3600) -> None:
    """Remove finished backups nobody downloaded within the hour (and leftovers of an interrupted run)."""
    try:
        for p in tmp_root().iterdir():
            if time.time() - p.stat().st_mtime > max_age:
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
    except OSError:
        pass


# ----------------------------------------------------------------- restore ---
def read_manifest(tar: tarfile.TarFile) -> dict[str, Any]:
    try:
        m = json.load(tar.extractfile("manifest.json"))  # type: ignore[arg-type]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("this is not a Looking Glass backup (manifest.json is missing)") from exc
    if m.get("app") != "looking-glass" or not isinstance(m.get("tables"), dict):
        raise ValueError("this is not a Looking Glass backup")
    if int(m.get("format", 0)) > FORMAT:
        raise ValueError(f"this backup was made by a newer Looking Glass ({m.get('version')}): update first")
    return m


async def restore(file: str, data_dir: str, log_fn=print) -> dict[str, Any]:
    """Restore a backup into the connected database (db.pool()) and put its key in place."""
    from . import db_config

    src = Path(file)
    if not src.is_file():
        raise FileNotFoundError(f"{file} not found (copy it into the data folder, it is /data inside the container)")
    work = Path(tempfile.mkdtemp(prefix="restore-", dir=tmp_root()))
    try:
        with tarfile.open(src, "r:gz") as tar:
            m = read_manifest(tar)
            names = set(tar.getnames())
            for t in m["tables"]:
                if f"tables/{t}.csv" not in names:
                    raise ValueError(f"the backup is incomplete: tables/{t}.csv is missing")
            if "lookingglass.key" not in names:
                raise ValueError("the backup has no encryption key")
            for member in tar.getmembers():  # only the expected plain files, never paths outside the folder
                if member.isfile() and (member.name == "lookingglass.key" or
                                        (member.name.startswith("tables/") and member.name.count("/") == 1
                                         and member.name.endswith(".csv"))):
                    tar.extract(member, work, filter="data")
        log_fn(f"backup of {m['created']} (Looking Glass {m.get('version')}, {m['kind']}): {len(m['tables'])} tables")
        async with db.pool().acquire() as conn:
            current = await tables(conn)
            todo = [t for t in m["tables"] if t in current]
            skipped = [t for t in m["tables"] if t not in current]
            for t in todo:
                gone = [c for c in m["tables"][t]["columns"] if c not in current[t]]
                if gone:
                    raise ValueError(f"table {t}: the columns {', '.join(gone)} no longer exist in this version - "
                                     "restore with the Looking Glass version that made the backup")
            order = [t for t in todo if t not in LATE] + [t for t in todo if t in LATE]
            async with conn.transaction():
                await conn.execute(f"TRUNCATE {', '.join(_q(t) for t in todo)} CASCADE")
                for t in order:
                    cols = m["tables"][t]["columns"]
                    await conn.copy_to_table(t, source=str(work / "tables" / f"{t}.csv"), columns=cols, format="csv")
                    log_fn(f"  {t}: {m['tables'][t]['rows']} rows")
                # id sequences continue after the restored rows
                for t in todo:
                    seq = await conn.fetchval("SELECT pg_get_serial_sequence($1, 'id')", t) if "id" in current[t] else None
                    if seq:
                        await conn.execute(f"SELECT setval($1, coalesce((SELECT max(id) FROM {_q(t)}), 0) + 1, false)", seq)
                # event ids may now be lower than the detection rules / rollup remember: start those again
                max_id = await conn.fetchval("SELECT coalesce(max(id), 0) FROM events")
                await conn.execute("DELETE FROM kv WHERE key LIKE 'wm:%'")
                await conn.execute("UPDATE event_rollup_state SET upto = least(upto, $1), seen = least(seen, $1)", max_id)
                await conn.execute("INSERT INTO event_rollup_state (one) VALUES (true) ON CONFLICT DO NOTHING")
        # the key: the backup's one replaces the current one (kept next to it), the saved database connection is
        # encrypted again with it
        key = crypto.key_path(data_dir)
        new_key = (work / "lookingglass.key").read_bytes().strip()
        old_key = key.read_bytes().strip() if key.exists() else None
        if old_key != new_key:
            cfg = db_config.load(data_dir)
            if old_key is not None:
                kept = key.with_name(f"{key.name}.before-restore-{datetime.now():%Y%m%d-%H%M%S}")
                kept.write_bytes(old_key)
                os.chmod(kept, 0o600)
                log_fn(f"the previous encryption key is kept as {kept}")
            try:
                tmp = key.with_suffix(".tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(new_key)
                os.replace(tmp, key)
            except OSError as exc:
                raise OSError(f"the data was restored, but the key file {key} cannot be written ({exc}). Put the "
                              "lookingglass.key from the backup there yourself, or the stored credentials cannot be "
                              "read") from exc
            crypto.init(data_dir)
            if cfg:
                db_config.save(data_dir, cfg)
            log_fn("encryption key restored")
        return {"tables": todo, "skipped": skipped, "manifest": m}
    finally:
        shutil.rmtree(work, ignore_errors=True)

