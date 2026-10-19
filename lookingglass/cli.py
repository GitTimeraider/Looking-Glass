"""Command line helpers, run inside the container:

    docker exec -it looking-glass python -m lookingglass.cli reset-code
        -> prints a reset code into the container log (same as the "Forgot password" button)

    docker exec looking-glass python -m lookingglass.cli setup-database
        -> forgets the database connection saved by the setup wizard; after a restart
           (docker restart looking-glass) the wizard asks for it again. Data in the database is kept.
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
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
