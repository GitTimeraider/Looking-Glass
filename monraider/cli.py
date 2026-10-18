"""Command line helpers, run inside the container:

    docker exec -it monraider python -m monraider.cli reset-code
        -> prints a reset code into the container log (same as the "Forgot password" button)
"""
from __future__ import annotations

import sys
import urllib.request


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-code":
        req = urllib.request.Request("http://127.0.0.1:8080/reset/request", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - local only
            r.read()
        print("A reset code was written to the container log: docker logs monraider --tail 20")
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
