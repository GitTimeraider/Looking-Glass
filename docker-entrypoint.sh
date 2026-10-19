#!/bin/sh
# The image runs as uid/gid 10001 by default; choose another with `--user <uid>:<gid>` (compose: `user:`).
# Started that way it needs no capabilities at all (--cap-drop=ALL, --security-opt=no-new-privileges:true).
#
# Legacy mode: when the container is started as root (`--user 0` / `user: root`), /data is chowned to PUID/PGID and
# privileges are dropped with setpriv. That mode needs the capabilities CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID.
set -e
DATA_DIR="${DATA_DIR:-/data}"
KEY_FILE="${LG_ENCRYPTION_KEY_FILE:-$DATA_DIR/lookingglass.key}"

if [ "$(id -u)" = "0" ]; then
    PUID="${PUID:-10001}"
    PGID="${PGID:-10001}"
    if ! { mkdir -p "$DATA_DIR" && chown "$PUID:$PGID" "$DATA_DIR" \
           && { [ ! -f "$KEY_FILE" ] || { chown "$PUID:$PGID" "$KEY_FILE" && chmod 600 "$KEY_FILE"; }; }; } 2>/dev/null; then
        echo "ERROR: started as root but cannot fix the ownership of $DATA_DIR (capabilities dropped?)." >&2
        echo "       Start the container as a normal user instead: --user $PUID:$PGID (compose: user: \"$PUID:$PGID\")," >&2
        echo "       or add back: --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETUID --cap-add=SETGID" >&2
        exit 1
    fi
    if ! setpriv --reuid="$PUID" --regid="$PGID" --clear-groups true 2>/dev/null; then
        echo "ERROR: started as root but cannot switch to $PUID:$PGID (SETUID/SETGID capabilities dropped?)." >&2
        echo "       Start the container as a normal user instead: --user $PUID:$PGID (compose: user: \"$PUID:$PGID\")" >&2
        exit 1
    fi
    export HOME="$DATA_DIR"  # not /root: libpq/asyncpg look for ~/.postgresql and would hit "permission denied"
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$@"
fi

if [ -n "$PUID$PGID" ] && [ "${PUID:-$(id -u)}:${PGID:-$(id -g)}" != "$(id -u):$(id -g)" ]; then
    echo "WARNING: PUID/PGID are ignored; the container runs as $(id -u):$(id -g). Use --user <uid>:<gid>" \
         "(compose: user: \"<uid>:<gid>\") to choose the user." >&2
fi
if ! { [ -d "$DATA_DIR" ] && [ -w "$DATA_DIR" ] && [ -x "$DATA_DIR" ]; }; then
    echo "ERROR: $DATA_DIR is not writable for uid $(id -u) / gid $(id -g)." >&2
    echo "       On the Docker host, give the folder you mounted at $DATA_DIR to that user, e.g.:" >&2
    echo "         sudo chown -R $(id -u):$(id -g) ./data" >&2
    echo "       or start the container with the --user <uid>:<gid> that owns the folder." >&2
    exit 1
fi
if [ -f "$KEY_FILE" ] && ! [ -r "$KEY_FILE" ]; then
    echo "ERROR: the encryption key $KEY_FILE belongs to another user (owner uid $(stat -c %u "$KEY_FILE"))." >&2
    echo "       On the Docker host run: sudo chown -R $(id -u):$(id -g) <data folder>   (or use --user $(stat -c %u:%g "$KEY_FILE"))" >&2
    exit 1
fi
exec "$@"
