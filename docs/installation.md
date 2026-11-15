# Installation details

[← Back to the README](../README.md)

Everything around the install steps in the README: the setup wizard, MFA, settings, password reset, GeoIP, PostgreSQL, updates and database load.

## The database password file

Step 2 of the README writes the password for the bundled PostgreSQL to `secrets/db_password`. `chmod 644` on the file
is needed because the non-root containers must be able to read it; the `secrets` folder itself (`chmod 700`) stays
closed to other users on the host. If you prefer an existing PostgreSQL 14+ server, use
[`examples/docker-compose.external-postgres.yml`](../examples/docker-compose.external-postgres.yml).

## Start, run the setup wizard and log in

On the Docker host, in `~/looking-glass`:

```bash
docker compose up -d
docker compose logs looking-glass        # shows the one-time setup code
cat secrets/db_password                  # the database password, for the wizard
```

The log contains a block like:

```
FIRST-TIME SETUP: open the web UI (port 8080) and enter this setup code:
    K7QM-2XHD-9WPA
```

In your browser open `http://<docker-host>:8080`. The setup wizard asks for:

1. **Setup code** – from the log above. It makes sure only someone with access to the Docker host can set up a
   fresh instance. After 10 wrong attempts a new code is printed.
2. **Database** – for the bundled database keep the defaults (host `db`, port `5432`, database and user
   `lookingglass`) and paste the password from `secrets/db_password`. *Test connection* tells you exactly what is
   wrong (wrong password, unknown host, missing database, missing rights). *Save & continue* creates the tables.
   The connection is stored encrypted in `data/database.conf`. Pointing it at a database that already holds Looking
   Glass data reuses it.
3. **Account** – your user name and password (at least 10 characters).

You land on the login page. After logging in you are sent to **Account & MFA** and must set up a second factor
before anything else is accessible:

* **Authenticator app (TOTP)** – click *Set up authenticator app*, scan the QR code with Google/Microsoft
  Authenticator, Aegis, 1Password, Bitwarden…, type the 6-digit code, *Confirm*.
* **Passkey / security key** – type a name, click *Add passkey* and follow your browser / phone / YubiKey prompt.
  Passkeys only work when Looking Glass is opened over **HTTPS** (or `http://localhost`); use
  `examples/docker-compose.https.yml` or your own reverse proxy (Nginx Proxy Manager, Traefik, SWAG…).

Next logins ask for password + TOTP code or passkey.

> **Changing the database later** (other server, new password): shell on the Docker host,
> `docker exec looking-glass python -m lookingglass.cli setup-database`, then `docker restart looking-glass` and
> open the web UI – the wizard asks for the connection again (new setup code in the log). Your data and accounts
> stay in the database.

## Enter your integrations (Looking Glass web UI › **Settings**)

* **OPNsense** tab – URL (e.g. `https://192.168.1.1`), the API key and secret from [OPNsense setup](opnsense.md#create-the-api-user-and-key-opnsense-web-ui) → *Test connection* → *Save*.
* **AI analyst** tab – your Anthropic API key (<https://console.anthropic.com> › *API keys*). Base URL
  `https://api.anthropic.com/v1/` and model `claude-opus-5-5` are pre-filled; any other OpenAI-compatible service
  (OpenAI, OpenRouter, LiteLLM, Ollama at `http://host:11434/v1/` …) works by changing base URL, model and key.
  *Test connection* → *Save*. Optional: tick **Privacy mode** so the AI only ever sees pseudonyms instead of your local
  addresses and names (see [AI privacy mode](ai-analyst.md#ai-privacy-mode-pseudonyms)).
* **Ingestion & network** tab – set *Syslog allowed senders* to your OPNsense IP and your *Time zone*.
* **Display** tab – *Time format*: 24-hour (default, 14:05), 12-hour (2:05 PM) or your browser's default - for the
  web UI, notification mails and the AI analyst (mails and AI write times in your *Time zone*).
  *Theme*: dark (default), light, or auto (follows the browser / operating system), and an *Accent color* (purple is
  the default; blue, indigo, pink, red, crimson, dark red, orange, green, teal, cyan or gray) for buttons, links and a
  light tint of the background - e.g. light + purple, dark + purple. The page previews your pick right away; *Save*
  keeps it.
  *Menu bar position*: top (default), bottom, left or right - top / bottom are a horizontal bar whose sections open as
  menus, left / right a sidebar. Phones always use the menu button.
  *Corners*: square (default) or rounded, for cards, widgets, buttons and fields.
  *Application name*: the name on the menu bar, the login page and the browser tab (empty = Looking Glass).
  *Logo on the menu bar*: upload a picture (PNG, JPEG, GIF, WebP or SVG, at most 256 KB) shown in front of the name.
  *Browser tab icon (favicon)*: upload your own icon instead of the built-in magnifier.
  **Restore defaults** puts every display setting (including name, logo and favicon) back to the built-in values.
* **Unraid servers** / **Data & detection** tabs – optional (see [Unraid](unraid.md), [UniFi](unifi.md) and [Backups](backups.md)).

Everything applies immediately. API keys, secrets and passwords are encrypted (Fernet/AES) with a key that is
generated on first start in the data volume (`/data/lookingglass.key`, readable only by the app user). They are
never shown again in the UI or API - a field only says *set* / *not set*. **Back up `./data/lookingglass.key`
together with your database**; without it the stored credentials can't be decrypted (you would just re-enter them).

> Upgrading from a version that used `OPNSENSE_*`, `AI_*`, `UNRAID_*` … environment variables? They are imported
> into the encrypted store automatically on the first start (the log tells you which) – then delete them from your
> compose/.env file.

> Upgrading from a version with `DATABASE_URL` / `POSTGRES_PASSWORD` / `ADMIN_*` in `.env`? It keeps working
> unchanged (`DATABASE_URL` from the environment takes precedence over the wizard). To get rid of them: download the
> new `docker-compose.yml`, write your current `POSTGRES_PASSWORD` into `secrets/db_password` (commands in step 2 of the README,
> e.g. `grep ^POSTGRES_PASSWORD= .env | cut -d= -f2- > secrets/db_password`), delete `POSTGRES_PASSWORD`,
> `DATABASE_URL`, `ADMIN_USER` and `ADMIN_PASSWORD` from `.env`, run `docker compose up -d` and complete the wizard
> (database step only - your accounts and data are kept). PostgreSQL only reads its password when it creates the
> database, so the existing database keeps its password.

> Port 514 on the host must be free. If something else uses it, change `"514:5514/udp"` in `docker-compose.yml`
> to e.g. `"1514:5514/udp"` and use that port in OPNsense (see [OPNsense setup](opnsense.md#send-logs-from-opnsense-opnsense-web-ui)).

## Forgot the password or lost the MFA device?

1. On the login page click **Forgot password / lost MFA device?** (or open `http://<docker-host>:8080/reset`) and
   click **Generate reset code**.
2. Read the code from the container log – shell on the Docker host: `docker logs looking-glass --tail 20`
   (Unraid: Docker tab › Looking Glass icon › *Logs*; Portainer: *Containers › looking-glass › Logs*). It looks like
   `Reset code: 7F3A-91BC (valid 15 minutes, single use)`.
   Alternatively create a code from the shell: `docker exec looking-glass python -m lookingglass.cli reset-code`.
3. Enter the code and a new password on the reset page. Password **and** all MFA factors are reset; you set up
   MFA again at the next login. Codes are single use, expire after 15 minutes and are destroyed after 5 wrong attempts.


## Optional: GeoIP countries (shell on your Docker host)

Create a free account at MaxMind, download **GeoLite2-City.mmdb** (or Country) and place it in `~/looking-glass/data/`,
then `docker compose restart looking-glass`. Make sure the file belongs to the container user
(`sudo chown -R 10001:10001 ~/looking-glass/data`, or your `PUID:PGID`).

> **PostgreSQL 18:** the compose files use the official `postgres:18` image. Its volume goes at `/var/lib/postgresql`,
> not `/var/lib/postgresql/data` as in 17 and older. Mounted at the old path, it refuses to start. Fresh installs need
> nothing extra.

> **`could not resize shared memory segment … No space left on device`** on a dashboard: Docker gives a container
> only 64 MB of `/dev/shm`, and PostgreSQL's parallel queries run out of it once the tables grow. The compose files
> set `shm_size: 512mb` on the `db` service. Older compose file: add that line under `db:` (next to `restart:`), then
> run `docker compose up -d` in `~/looking-glass` on the Docker host. PostgreSQL as a separate container (Unraid,
> Portainer …): add `--shm-size=512m` to its *Extra Parameters* / run options. Can't change it (external server)?
> Run `ALTER SYSTEM SET max_parallel_workers_per_gather = 0; SELECT pg_reload_conf();` in `psql` as a superuser.

## Switching an existing database from `postgres:18-alpine` to `postgres:18`

Compose files before October 2026 used `postgres:18-alpine`. The two images differ in two ways that matter for an
existing database:

* The `postgres` user is uid **70** in Alpine and **999** in the Debian-based `postgres:18`. Without a chown, the new
  image can't read the old files and refuses to start.
* Text sorts differently (musl vs glibc). Indexes built by Alpine are out of order for the new image, so lookups can
  silently miss rows until the indexes are rebuilt. In a test, a lookup for an existing row returned 0 rows before
  `reindexdb` and 1 after.

Shell on the Docker host, in `~/looking-glass`, after downloading the new `docker-compose.yml`:

```bash
docker compose stop
# give the database files to the new image's postgres user (uid 999)
docker compose run --rm --no-deps --user root --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --entrypoint chown db -R postgres:postgres /var/lib/postgresql
docker compose up -d db
docker compose exec db reindexdb -U lookingglass --all     # rebuild indexes for the new sort order
docker compose up -d
```

Running PostgreSQL as a separate container on Unraid? Stop it and change its image to `postgres:18`. In the Unraid
terminal run `chown -R 999:999 /mnt/user/appdata/<db folder>`. Start the container, then run
`docker exec <db container> reindexdb -U lookingglass --all`.

You can also stay on `postgres:18-alpine`: keep that image name in your compose file and nothing changes.

## Updating (shell on your Docker host, in `~/looking-glass`)

```bash
docker compose pull && docker compose up -d
```

Upgrading from a version that started as root and used `PUID`/`PGID` to drop privileges: download the new
`docker-compose.yml` (it adds `user: "${PUID}:${PGID}"`, `cap_drop` and `no-new-privileges`). Your `data` folder
already belongs to `PUID:PGID`, so nothing else changes. Running with `docker run` instead of compose? Add
`--user <PUID>:<PGID>`; without it the container runs as 10001:10001 and prints a warning that `PUID`/`PGID` are
ignored.

## Dashboards and database load

Dashboards count a lot of log lines, so Looking Glass keeps that work small:

* **Hourly counts**: charts and counts over 2 days or more (time series, protocols, ports, countries, interfaces …)
  come from a small table of hourly totals that is updated every minute from the new events only - the same numbers as
  counting every event, a fraction of the work (30 days: ~16× less). After an update the existing events are counted
  once in the background, in small slices; until then those panels count the raw events as before.
* **Indexes for the dashboards**: blocked traffic, the CrowdSec / Q-Feeds blocklist lines and the per-source counts
  are read from narrow indexes instead of the whole log lines with their message and data (30 million events: the
  Q-Feeds table went from over 3 minutes to a few seconds, the "top blocked" tables read ~1 GB instead of ~14 GB).
  After an update they are built **once, in the background**, shortly after the start - on a large database this takes
  a few minutes (the log says `building index ...` and `index ... built`), events keep arriving meanwhile, and the
  dashboards get faster when it is done. They take about 2 GB extra disk space per 30 million events.
* **Refresh**: a page only refreshes while its tab is visible (a tab in the background does nothing, and catches up
  when you open it again); 24 h views every minute, 7 days every 5 minutes, 30 days every 15 minutes.
* **Shared results**: tabs, devices and users looking at the same dashboard and period share one result for a short
  while (30 s for up to a day, 2 / 5 minutes for 7 / 30 days).
* **No spikes**: at most 3 heavy queries run at once, instead of every panel of a page at the same time.
* **Database memory**: the compose files start PostgreSQL with `shared_buffers=512MB` (the default 128 MB is too small
  for the log tables once they hold a few days). **Existing installation?** Add this line to the `db:` service of your
  `docker-compose.yml` (at the same level as `image:`) and run `docker compose up -d`:

  ```yaml
      command: ["postgres", "-c", "shared_buffers=512MB", "-c", "effective_cache_size=2GB"]
  ```

  PostgreSQL as a separate container from an **Unraid template**: Docker tab › the container › *Edit* › *Advanced
  view* › **Post Arguments**: `-c shared_buffers=512MB -c effective_cache_size=2GB` › *Apply*. Use about a quarter of
  the memory you want the database to use (256MB on a small machine), and keep its data on an SSD (Unraid: the cache
  pool / `appdata`). Looking Glass itself sets `jit=off` and `work_mem=16MB` for its own connections, also on an
  external PostgreSQL.
