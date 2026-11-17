# Unraid

[← Back to the README](../README.md)

Adding Unraid servers: what is shown, alerts, spun-down disks and container packages.

## Adding an Unraid server

1. **Unraid web UI** (Unraid 7.2+ has the API built in; on 6.12–7.1 install the *Unraid Connect* plugin from
   Community Apps first): *Settings › Management Access › API Keys › Create*, name `lookingglass`, role **Viewer**,
   copy the key. (Or in the Unraid terminal: `unraid-api apikey --create --name lookingglass --roles VIEWER --json`.)
2. **Looking Glass web UI**: *Settings › Unraid servers* › fill in name, URL (e.g. `http://192.168.1.10`) and the API key ›
   *Test connection* › *Add server*. Add as many servers as you like.
3. CPU / memory per container comes from the Unraid API (version 4.29 or newer; the version is shown on the
   Unraid page). Only on an older API: on Unraid start
   [`examples/docker-compose.unraid-socket-proxy.yml`](../examples/docker-compose.unraid-socket-proxy.yml)
   (a read-only Docker API) and enter `http://<unraid-ip>:2375` as *Docker API* for that server.
   The same Docker API (with `IMAGES=1`) also lets *Unraid › Packages* read exactly the image each container runs -
   see [Container packages](#container-packages-unraid--packages).

The **Unraid** page then shows:
* **Overview**: CPU/cores, memory, temperatures, network, VMs, UPS.
* **Array, pools & disks**: the array and each pool separately (e.g. a ZFS SSD pool), with capacity, file system,
  member disks, spinning / spun-down state, temperature, errors, parity check, shares and SMART. Charts show
  spinning disks and usage per array/pool.
* **Docker**: containers, state (with an *unhealthy* mark when the container's health check fails), updates, CPU/memory, restarts in the last hour, and the **log alert rules** (below). Container CPU is the share of the whole CPU (all threads), like the server's own CPU graph - not `docker stats`' 100 % per thread.
* **Logs**: container logs and the Unraid syslog, searchable.
* **Notifications**.
* **Packages** (optional, switched on under *Settings › Unraid servers › Container packages*): every image in use and
  every package inside it, searchable - see [Container packages](#container-packages-unraid--packages).

These become Looking Glass alerts: disk errors or overheating, stopped auto-start containers, containers that keep
restarting, unhealthy containers (their Docker health check keeps failing), too many errors in a container log, array problems, ZFS
errors in the Unraid syslog (`zed` device faults, checksum/I/O errors), UPS on battery and Unraid *warning/alert*
notifications.

Reboots stay quiet (both under *Settings › Data & detection*, default 10 minutes):

* **Unraid: unreachable alerts wait** - "Unraid server … is unreachable" only once Looking Glass has not reached the
  server for that long, so rebooting the server, or OPNsense in between, raises no alert. It closes by itself when the
  server answers again (with how long it was unreachable). 0 = after 3 failed polls (about 45 seconds).
* **Unraid: container alerts wait** - no "container stopped" alert while the server is still starting its containers
  after a reboot; it closes by itself once the container runs again.

**Unhealthy containers** - a container whose image has a health check (`HEALTHCHECK`, or `--health-cmd` in *Extra
Parameters*) shows *(unhealthy)* in its status when that check keeps failing: it runs, but does not work. Looking
Glass alerts (medium) once it has been unhealthy for *Settings › Data & detection › Unraid: unhealthy alerts wait*
(default 5 minutes, 0 = off) and closes the alert by itself when the check passes again.

**Containers that keep restarting** - a container that crashes right after it starts and is restarted by Docker over
and over (a restart policy such as `--restart=unless-stopped`). Looking Glass reads the start / crash time from each
container's status ("Up 5 seconds", "Restarting (1) 20 seconds ago") on every poll. 2-3 restarts (an update, a manual
restart, a reboot) stay quiet; *Settings › Data & detection › Unraid: container keeps restarting from* (default 5
restarts within 15 minutes, 0 = off) sets when it alerts (medium; high at 3× the limit). The alert closes by itself
once the container has not restarted for twice that time. The Docker tab shows the restarts of the last hour per
container. A crash loop that restarts much faster than the poll interval is counted lower than it is - it still alerts.

> **Use a Docker API for complete container logs.** The Unraid API returns only what a container writes to
> **stdout**; everything written to **stderr** - nginx `[emerg]` / `[error]`, most crash messages and tracebacks -
> is missing there. With a *Docker API* (docker-socket-proxy with `CONTAINERS=1`, see the setup above) set for the
> server, logs are read from it first, with both streams; the Unraid API is only the fallback. *Unraid › Docker* says
> so when logs come from the Unraid API.

**Errors in container logs** (needs *Collect logs* on the server) - every container is different, so what counts is up
to you, under **Unraid › Docker › Log alert rules** (or *rule* under *logs* next to a container):

| Field | Meaning |
|---|---|
| Containers | names, one per line, `*` / `?` wildcards; empty = every container. Optionally only one server |
| Lines that count | one per line: text the line contains (case does not matter) or a `/regular expression/` (`\b` works as a word boundary). Empty = error lines: a level of error or worse (`[error]`, `[emerg]`, `level=error`, `ERROR`, `FATAL` …), or - for lines without a level - the words error, fatal, panic, exception, traceback or critical |
| Except lines with | same format: known harmless lines that never count (`0 errors`, `deprecated`) |
| Alert from … within … | that many lines in that many minutes; **0 = no log alerts for these containers** |
| Severity | of the alert |

A container with its own rule(s) uses only those (each rule its own alert); every other container uses the default
rule from *Settings › Data & detection › Unraid: container log errors from* (default 50 error lines in 10 minutes,
0 = off). **Emergency / critical lines** (`[emerg]` / `[alert]` / `[crit]` of nginx, `FATAL`, `PANIC`, `level=fatal`)
raise their own alert from the first line (*Unraid: emergency / critical log lines from*, default 1 in those minutes,
severity high) - for every container, also one with its own rules, unless one of them has limit 0. A container it
alerts for gets no second "error lines" alert. **Test against the last 24 hours** shows, before you save, how many lines a rule finds per container, its
busiest window and how often it would have alerted. Alerts show the newest matching lines, link to them in Event
search, and close by themselves once three windows of the rule together stay below the limit.

## Spun-down disks are never woken

Array and pool status (including disk temperatures, which Unraid itself only reads while a disk spins) comes from
Unraid's own state files. Reading those never touches a disk. Only two Unraid API calls touch the disks, and Looking
Glass only sends them while **every** array/pool hard disk was already spinning in the last two readings:

* **SMART check** (physical disks). The Unraid API runs `smartctl -a` on *every* disk for it, which wakes all of them.
  It is off by default. Turn it on per array/pool under *Settings › Unraid servers › arrays & pools* (every hour …
  weekly).
* **Temperature sensors** (CPU, board, NVMe). Up to Unraid API 4.37.5 they also run `smartctl` on every disk
  ([unraid/api#2017](https://github.com/unraid/api/issues/2017), fixed by
  [#2091](https://github.com/unraid/api/pull/2091) after the 4.37.5 release). On those versions *Auto* reads them every 10 minutes
  while all disks spin anyway. Newer API versions read them every poll. Set them to *Off* if you don't need them.

The SMART query and the old-API temperature sensors also touch disks outside the array and pools (e.g. Unassigned
Devices). Their spin state isn't reported by the API, so leave the SMART check off if you have such disks and want
them asleep.

*Settings › Unraid servers › arrays & pools* also lets you **exclude** an array or pool completely: no dashboard, no
metrics, no alerts.

> ZFS pool health (`zpool status`: vdev layout, scrub results) is not available through the Unraid API. Looking Glass
> shows ZFS pools with capacity and member devices, and alerts on ZFS errors from the Unraid syslog (enable *collect
> container & system logs*) and on Unraid's own notifications.


## Container packages (Unraid › Packages)

What is inside the image of every container on your Unraid servers: operating system packages (deb / rpm / apk),
libraries, language packages (PHP Composer, Python, npm, Go modules, Java…) and the programs they are built into.
Read with [Syft](https://github.com/anchore/syft), which is included in the Looking Glass image. It only lists the
parts - there is no vulnerability checking.

**Set it up**

1. Optional, but recommended: a read-only Docker API on each Unraid server, so the exact image each container runs
   is read. **Unraid web UI** › *Docker* tab › your `docker-socket-proxy` container › *Edit* › *Add another Path,
   Port, Variable…* › Variable, key `IMAGES`, value `1` › *Apply* (it also needs `CONTAINERS=1`; `POST=0` keeps it
   read-only). No proxy yet? Start
   [`examples/docker-compose.unraid-socket-proxy.yml`](../examples/docker-compose.unraid-socket-proxy.yml) on Unraid,
   then enter `http://<unraid-ip>:2375` as *Docker API* under **Looking Glass › Settings › Unraid servers** › your
   server.
2. **Looking Glass web UI** › *Settings › Unraid servers* › card **Container packages** › tick **Read the packages
   of container images** › *Save*.
3. **Looking Glass › Unraid › Packages** (`/unraid#packages`): every image is read once (they are all new), which
   can take a few minutes; the state is shown at the top of the tab.

**What the tab shows**

* **Images** - every image in use on all your Unraid servers: its containers, base OS (e.g. *Debian GNU/Linux 13*),
  number of packages, when and how it was read (or the error), an **Update** button per image and **Update all**.
  Clicking the number of packages lists them below.
* **Packages** - every package of every image: name, version, type, language, image and containers, and where in
  the image it is. **Search** looks in all of that (every word must match): `php` shows every container with PHP
  inside, `openssl nextcloud` the OpenSSL of Nextcloud. Filters for **type**, **language** and **image** (with how
  many packages each has). At most 1000 rows are shown at a time; the count says when to narrow the search.

**When an image is read** - only:

* when it is **new** (a container you just added),
* when it is **updated** (a container runs a new image: a new digest, or - without a Docker API - the container was
  recreated by Unraid), and then **only that image**,
* when you press **Update** on one image or **Update all**.

Never on a schedule. Images no container uses any more are removed from the list.

**Image source** (*Settings › Unraid servers › Container packages › Image source*) - where Syft gets the image:

| Source | How | Use when |
|---|---|---|
| **auto** (default) | from the registry by the exact digest the container runs; without a known digest through the Docker API; without a Docker API the registry's current image of the tag | always works; exact whenever a Docker API with `IMAGES=1` is set up |
| **docker** | exported through the server's Docker API (needs `IMAGES=1`) | every server has a Docker API, and you want nothing downloaded from the internet |
| **registry** | only from the registry (by digest when known, else the tag) | no Docker API, and images are only from public registries |

The package list is **the same** with *docker* and with *auto* / *registry* by digest: Syft reads the same image
files either way. *docker* is always the image that actually runs (also when the digest is unknown, and for the
processor your server has) and also reads images you built yourself, which are in no registry. Keep in mind:

* with *docker*, a server **without** a Docker API can't be read at all (an error per image); *auto* falls back to
  the registry,
* the whole image goes over your network from Unraid to Looking Glass each time it is read, and Unraid does the
  export work - very large images may need a higher **Time limit per image**.

**Connections it makes** - only when an image is read:

* the **Docker API** of your Unraid server (in your own network): which image each container runs, and the image
  export with source *docker* or *auto*,
* the image's **registry** (Docker Hub, ghcr.io, lscr.io, …) with source *auto* or *registry*: Syft downloads the
  image to read it - the same registries Unraid pulls the images from. With **Registry login** set, it logs in
  there (Docker Hub limits anonymous pulls; private registries need a login).

Nothing else: no vulnerability or package databases, and Syft's own update check is switched off. With source
*docker* nothing goes to the internet at all; switched off, it makes no connections.

**Other settings** under *Container packages*: **Containers / images not to read** (names or images, `*` as
wildcard), **Syft program** (included; change only to use another one), **Extra Syft arguments** (e.g.
`--platform linux/arm64`), **Extra environment for Syft** (`NAME=value` per line, e.g. a proxy) and **Time limit per
image** (default 30 minutes).

The package lists are kept in `/data/packages` (one small file per image).
