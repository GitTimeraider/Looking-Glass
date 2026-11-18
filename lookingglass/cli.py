"""Command line helpers, run inside the container:

    docker exec -it looking-glass python -m lookingglass.cli reset-code
        -> prints a reset code into the container log (same as the "Forgot password" button)

    docker exec looking-glass python -m lookingglass.cli setup-database
        -> forgets the database connection saved by the setup wizard; after a restart
           (docker restart looking-glass) the wizard asks for it again. Data in the database is kept.

    docker compose stop looking-glass
    docker compose run --rm looking-glass python -m lookingglass.cli restore /data/<backup>.tar.gz
    docker compose start looking-glass
        -> restores a backup made under Settings › Data & detection › Backup (copy the file into the data
           folder first). Replaces the data in the database and puts the backup's encryption key in place.
"""
from __future__ import annotations

import os
import sys
import urllib.request


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-code":
        req = urllib.request.Request("http://127.0.0.1:8080/reset/request", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - local only
            r.read()
        print("A reset code was written to the container log: docker logs looking-glass --tail 20")
    elif cmd == "setup-database":
        from . import db_config
        data_dir = os.environ.get("DATA_DIR", "/data")
        if os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_URL_FILE"):
            print("DATABASE_URL is set in the environment and takes precedence - remove it to use the wizard.")
        if db_config.delete(data_dir):
            print("Saved database connection removed. Restart the container (docker restart looking-glass) and open "
                  "the web UI; the setup code is in the container log.")
        else:
            print("No saved database connection found.")
    elif cmd == "restore":
        if len(sys.argv) < 3:
            print("usage: python -m lookingglass.cli restore /data/<backup>.tar.gz [--yes]")
            sys.exit(1)
        sys.exit(restore(sys.argv[2], "--yes" in sys.argv[3:]))
    else:
        print(__doc__)
        sys.exit(1)


def restore(file: str, yes: bool) -> int:
    import asyncio
    import logging

    from . import backup, crypto, db, db_config
    from .config import get_settings

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    s = get_settings()
    try:
        crypto.init(s.data_dir)
    except crypto.KeyFileError as exc:
        print(f"ERROR: {exc}")
        return 2
    if s.database_url:
        conn: dict = {"dsn": s.database_url}
    elif cfg := db_config.load(s.data_dir):
        conn = db_config.connect_kwargs(cfg)
    else:
        print("ERROR: no database connection yet. Start Looking Glass once and finish the setup wizard (it creates the "
              "connection), stop it again, then restore.")
        return 2
    if not yes:
        print(f"This REPLACES the data in the Looking Glass database with the backup {file}.")
        print("Stop Looking Glass first (docker compose stop looking-glass) - this command runs in its own container.")
        if input("Type RESTORE to continue: ").strip() != "RESTORE":
            print("Cancelled.")
            return 1

    async def run() -> int:
        dsn = conn.pop("dsn", None)
        await db.connect(dsn, retry=False, **conn)
        try:
            res = await backup.restore(file, s.data_dir)
        finally:
            await db.close()
        if res["skipped"]:
            print(f"not restored (unknown in this version): {', '.join(res['skipped'])}")
        print("Restore finished. Start Looking Glass again: docker compose start looking-glass")
        return 0

    try:
        return asyncio.run(run())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    main()
