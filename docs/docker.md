# Docker: running hardened

[← Back to the README](../README.md)

Running Looking Glass as non-root without any Linux capabilities.

## Running hardened (non-root, no capabilities)

The image runs as an unprivileged user (uid/gid **10001**) and needs **no Linux capabilities at all**, so all of
these work together without adding anything back:

| Option | `docker run` | compose |
|---|---|---|
| choose the user (and owner of `/data`) | `--user 99:100` | `user: "99:100"` |
| drop every capability | `--cap-drop=ALL` | `cap_drop: [ALL]` |
| block privilege escalation | `--security-opt=no-new-privileges:true` | `security_opt: ["no-new-privileges:true"]` |

All bundled compose files already set these. A complete `docker run` example (shell on your Docker host):

```bash
mkdir -p /srv/looking-glass && sudo chown 99:100 /srv/looking-glass
docker run -d --name looking-glass --restart unless-stopped \
  --user 99:100 --cap-drop=ALL --security-opt=no-new-privileges:true \
  -v /srv/looking-glass:/data \
  -p 8080:8080 -p 514:5514/udp -p 514:5514/tcp \
  ghcr.io/gittimeraider/looking-glass:latest
docker logs looking-glass    # setup code; then open http://<docker-host>:8080 for the wizard
```

Things to know:

* **The data folder must belong to the user you choose.** For a bind mount, run on the Docker host
  `sudo chown -R <uid>:<gid> <folder>` before starting. Docker creates a missing folder as root, and the container
  then stops with `ERROR: /data is not writable for uid … / gid …` and the exact command to run. A new **named
  volume** works with any `--user` without a chown, because `/data` in the image is world-writable with the sticky
  bit, like `/tmp`. The encryption key inside it is always created with mode `0600`.
* **Changing the user later:** chown the folder to the new uid:gid first, otherwise the container stops with
  `ERROR: the encryption key … belongs to another user`.
* The container ports (8080, 5514) are above 1024, so `NET_BIND_SERVICE` is not needed. Map host port 514 to
  container port 5514 as the examples do.
* Any uid/gid works; it doesn't have to exist inside the image.
* **Legacy root mode:** started as root (`--user 0`) with `PUID`/`PGID`, the container fixes the ownership of
  `/data` and then drops to `PUID:PGID`. Only that mode needs capabilities. With `--cap-drop=ALL` add back
  `--cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETUID --cap-add=SETGID`. It still works with
  `no-new-privileges`. Prefer `--user`.
* **PostgreSQL** (bundled `postgres:18`): started with `user: postgres` it skips its root start-up step and
  also runs with `cap_drop: [ALL]` and `no-new-privileges`, as in the compose files. Started as root (its default),
  it needs `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID` and `SETGID` back.
* **Docker secrets** (`examples/docker-compose.secrets.yml`): plain compose mounts the secret file with its host
  permissions, so non-root containers can only read it when it is `chmod 644`. Keep the `secrets` folder itself
  `chmod 700` to protect it on the host.
* **Caddy** (`examples/docker-compose.https.yml`) is left at its defaults. If you add `cap_drop: [ALL]` to it, add
  back `cap_add: [NET_BIND_SERVICE]` for ports 80/443.
* **Unraid template:** *Extra Parameters* already contains
  `--user=99:100 --cap-drop=ALL --security-opt=no-new-privileges:true`. Appdata shares belong to `nobody:users`
  (99:100), so it works as is.
