# Security notes

[← Back to the README](../README.md)

How logins, secrets and the AI analyst are protected, and how to run Looking Glass safely.

## Security notes

* Login = password (scrypt-hashed) + mandatory TOTP or passkey; failed logins are rate limited per IP and logged.
  Password changes and resets invalidate all other sessions.
* Put Looking Glass on your LAN / management network; don't expose port 8080 to the internet (use a VPN or a reverse
  proxy with TLS if you need remote access).
* The setup code and the reset code only appear in the container log, so setting up a fresh instance or resetting
  a login requires access to the Docker host. Until the wizard is finished, only the wizard is served.
* No passwords or API keys need to be in environment variables (which anyone who can run `docker inspect` can read).
  The database connection is stored encrypted in `/data/database.conf` (mode `0600`). The key is in the same
  folder, because the app must be able to start on its own. So the encryption protects copies of that one file,
  not someone who can read the whole data folder; that folder is readable only by the container user. The
  bundled PostgreSQL reads its password from `secrets/db_password` only when the database is first created.
* Integration credentials are stored encrypted in the database with a key kept only in the data volume, are
  never returned by the UI/API, and are not readable by the AI analyst's SQL tool. The environment holds no API keys.
* Set *Settings › Ingestion & network › Syslog allowed senders* to your OPNsense IP so nobody else can inject log lines.
* The AI's SQL tool runs inside read-only transactions with a statement timeout and only accepts `SELECT`.
* *Settings › AI analyst › Privacy mode* keeps your local addresses, MAC addresses and names away from the AI provider
  (it sees consistent pseudonyms) - see [AI privacy mode](ai-analyst.md#ai-privacy-mode-pseudonyms). For no data leaving your network
  at all, use a local model (Ollama, LM Studio).
