# Backups: Backrest and Bichon

[← Back to the README](../README.md)

Reading backup and mail-archive state from Backrest and Bichon.

## Adding Backrest (backups)

Optional. [Backrest](https://github.com/garethgeorge/backrest) is a web UI and scheduler for restic backups. Looking
Glass reads its plans, repositories and backup history over Backrest's own API; it never changes anything in Backrest
and does not need to be attached to the Backrest container.

1. **Backrest web UI** (`http://<unraid-ip>:9898`) › *Settings* › *Users*: add a user for Looking Glass (Backrest has
   no read-only users, so a separate one is best). Skip this when Backrest's authentication is disabled.
2. **Looking Glass web UI** › *Settings* › *Backrest*:
   * **Backrest URL (with port)** - the port is required, so a non-default port works too:
     `http://192.168.1.10:9898` (the Unraid host's IP and the port mapped in Docker), `http://backrest:9898` when
     both containers share a Docker network, or `https://backup.example.com:443` behind a reverse proxy.
   * **Username / Password** of that Backrest user.
   * **Test connection**, then **Save**.
3. If the test cannot connect: Looking Glass must reach that address. In **Unraid › Docker** check the port mapping of
   the Backrest container, or put both containers on the same custom Docker network.

What you get under **Infrastructure › Backups**:

* **Main** - every backup job of every backup tool (Backrest and Bichon): state (ok, warnings, failed,
  overdue, running), last and last successful run, next run, runs in the period, backups per day and the latest runs.
* **Backrest** - per plan and repository: schedule, retention, success rate, average and longest duration,
  **processing speed** (data scanned ÷ duration) and **upload speed** (new data added ÷ duration) per backup and on
  average, new data and data scanned per backup, repository size (stored and original), compression, snapshots over
  time, the last check / prune / forget, a running backup with its progress, current speed and time left, and every
  run with its error text.

Alerts (rules under *Backups* in Settings › Alert filters): **backup failed** (high when it keeps failing), **backup
finished with warnings** (low, can be switched off), **backup overdue** (no successful backup for longer than the
plan's schedule allows - the longest normal gap plus 25 % and 2 hours; or a fixed number of hours in Settings),
**repository check / prune / forget failed** and **Backrest unreachable**. They close by themselves once the next run
works. Repository passwords, cloud keys (restic environment variables) and Backrest's user hashes are dropped as soon
as the configuration is read - they are never stored. Runs are kept for 400 days, also after Backrest forgets them.

## Adding Bichon (mail archive)

Optional. [Bichon](https://github.com/rustmailer/bichon) archives mail accounts (IMAP) into a searchable archive.
Looking Glass reads the state of every account and sync over Bichon's own API (Bichon 2.3 or newer); it never changes
anything in Bichon and does not need to be attached to the Bichon container.

1. **Bichon web UI** (`http://<unraid-ip>:15630`) › *API tokens* › new token: tick **Metrics only**. That token can
   read Bichon's status figures and nothing else - no mail. Its user needs the `system:metrics` permission (an admin
   has it). Copy the token: Bichon shows it once.
2. **Looking Glass web UI** › *Settings* › *Bichon*:
   * **Bichon URL (with port)** - e.g. `http://192.168.1.10:15630` (the Unraid host's IP and the port mapped in
     Docker), `http://bichon:15630` when both containers share a Docker network, or
     `https://mail.example.com:443/bichon` behind a reverse proxy / with a base path.
   * **API token** - the token from step 1.
   * **Test connection**, then **Save**.
3. If the test cannot connect: Looking Glass must reach that address. In **Unraid › Docker** check the port mapping of
   the Bichon container, or put both containers on the same custom Docker network. *404* means the address is not
   Bichon's or Bichon is older than 2.3; *401* a wrong or revoked token.

**Metrics-only token or a normal token?** A metrics-only token is the safe choice. Bichon's metrics say only how the
*latest* sync of each account went, so Looking Glass builds the sync history itself from what it sees on every poll
(every 2 minutes by default): a sync that starts and ends between two polls is missed when another one follows before
the next poll, and "new mails" per sync stays empty. A normal token of a user that may read the accounts' details
(`account:read_details`, e.g. the *Account Viewer* role - which can also read the mail itself) gives Bichon's own sync
history instead: every sync with its result, the new mails and the folders that failed. Looking Glass tries that on
every poll and falls back to the metrics when the token may not.

What you get under **Infrastructure › Backups**:

* **Main** - every syncing mail account and Bichon's own backup are jobs next to the Backrest plans.
* **Bichon** - accounts, mails, attachments, mail storage and search-index size (and their growth over time), syncs,
  failures, partial syncs and success rate; a sync running now with its progress; duration and new mails per sync;
  per account: type, interval, last and last successful sync, mails, errors by kind since Bichon started (auth,
  network, throttled …) and gap-fill results; Bichon's own backup; every sync with its result and failed folders.

Alerts (the same rules as Backrest, under *Backups* in Settings › Alert filters): **mail sync failed**, **mail sync
finished with warnings** (Bichon: *Partial* - some folders could not be archived; can be switched off), **mail sync
overdue** (no successful sync for the account's interval plus 25 % and 2 hours, or a fixed number of hours), **Bichon
backup failed / overdue** (overdue only when you set its hours: the backup schedule cannot be read with the token) and
**Bichon unreachable**. They close by themselves once the next sync works.
