#!/bin/sh
# Make the data volume writable for the app user, then drop root privileges.
# PUID/PGID (default 10001) let Unraid / NAS users match their share permissions (e.g. PUID=99 PGID=100).
set -e
PUID="${PUID:-10001}"
PGID="${PGID:-10001}"
DATA_DIR="${DATA_DIR:-/data}"
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown "$PUID:$PGID" "$DATA_DIR"
    # the encryption key must only be readable by the app user
    [ -f "$DATA_DIR/lookingglass.key" ] && chown "$PUID:$PGID" "$DATA_DIR/lookingglass.key" && chmod 600 "$DATA_DIR/lookingglass.key"
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$@"
fi
exec "$@"
