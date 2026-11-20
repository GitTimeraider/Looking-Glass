"""SWAG (linuxserver.io's nginx reverse proxy with fail2ban) on the same Docker host: its log files.

SWAG writes everything to /config/log (on Unraid: /mnt/user/appdata/swag/log). That folder is mounted read-only into
the Looking Glass container (Settings › SWAG & CrowdSec › SWAG log folder) and followed like ``tail -F``:

* nginx access logs (default ``nginx/access.log``, combined format) -> source ``nginx``, program ``swag``: the same
  events as the OPNsense nginx plugin, so the web attack / scanner detections, the reports and the AI see them too;
* nginx error logs (``nginx/error.log``) -> the same, incl. rate limiting, ``access forbidden by rule`` and the
  CrowdSec nginx bouncer's ``[Crowdsec] denied '<ip>' with 'ban'`` lines (bouncer_block, or waf_block for AppSec);
* fail2ban (``fail2ban/fail2ban.log``) -> source ``fail2ban``: matches, bans, unbans per jail;
* honeypot: requests and jails that are traps (Settings › SWAG & CrowdSec › Honeypot) get the tag ``honeypot``.

Where each file was read up to (inode + offset) is kept in the database, so a restart neither reads lines twice nor
misses any; a log that logrotate renamed (``access.log`` -> ``access.log.1``) is read to its end first. The first
time a log is seen, its last ``swag_backfill_mb`` MB are read so the dashboards are not empty.
"""
from __future__ import annotations

import asyncio
import fnmatch
import glob
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo

from . import db
from .config import Settings
from .parsers import fail2ban as f2b
from .parsers import nginx as nginx_parser

log = logging.getLogger("lookingglass.swag")

PROGRAM = "swag"
STATE_KEY = "swag:tail"
STATUS_KEY = "swag:status"
READ_EVERY = 5.0  # seconds between two reads of the logs
CHUNK = 4 * 1024 * 1024  # at most this much per file and read: a large backlog is read over several rounds
_ERR_TIME = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) ")


def split_list(value: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,;\n]+", value or "") if p.strip()]


class Honeypot:
    """Settings › SWAG & CrowdSec › Honeypot: paths (/x, * = wildcard, else a prefix), host names, ``jail:<name>``
    and ``file:<log file>``. Jails / log files with 'honeypot' in their name always count."""

    def __init__(self, spec: str) -> None:
        self.paths: list[str] = []
        self.hosts: set[str] = set()
        self.jails: set[str] = set()
        self.files: set[str] = set()
        for item in split_list(spec):
            low = item.lower()
            if low.startswith("jail:"):
                self.jails.add(low[5:].strip())
            elif low.startswith("file:"):
                self.files.add(item[5:].strip().lstrip("/"))
            elif item.startswith("/"):
                self.paths.append(item)
            elif low.startswith("host:"):
                self.hosts.add(low[5:].strip())
            else:
                self.hosts.add(low)

    def file(self, rel: str) -> bool:
        return rel in self.files or "honeypot" in os.path.basename(rel).lower()

    def request(self, path: str | None, host: str | None) -> bool:
        if host and host.lower().split(":")[0] in self.hosts:
            return True
        p = (path or "").split("?", 1)[0]
        if not p:
            return False
        for pat in self.paths:
            if "*" in pat or "?" in pat:
                if fnmatch.fnmatchcase(p.lower(), pat.lower()):
                    return True
            elif p.lower().startswith(pat.lower()):
                return True
        return False


def mark_honeypot(ev: dict[str, Any]) -> None:
    data = ev.setdefault("data", {})
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    if "honeypot" not in tags:
        data["tags"] = [*tags, "honeypot"]
    data["honeypot"] = True
    ev["severity"] = min(int(ev.get("severity") or 6), 4)


def parse_line(kind: str, line: str, rel: str, name: str, tz: Any, honeypot: Honeypot,
               now: datetime | None = None) -> dict[str, Any] | None:
    """One line of a SWAG log -> event (None = nothing worth keeping). ``kind``: access, error or fail2ban."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    now = now or datetime.now(timezone.utc)
    if kind == "fail2ban":
        ev = f2b.parse(line, tz, host=name, honeypot_jails=frozenset(honeypot.jails))
        if ev is None:
            return None
        if honeypot.file(rel):
            ev.setdefault("data", {})["honeypot"] = True
    else:
        ts = now
        if kind == "error" and (m := _ERR_TIME.match(line)):
            try:  # nginx error log times are the container's local time without a zone
                ts = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz)
            except ValueError:
                pass
        ev = nginx_parser.parse(ts, name, PROGRAM if kind == "access" else f"{PROGRAM}-error", line)
        if ev is None:
            return None
        ev["program"] = PROGRAM
        data = ev.setdefault("data", {})
        path = data.get("path")
        if path is None and data.get("request"):
            parts = str(data["request"]).split(" ")
            path = parts[1] if len(parts) > 1 else parts[0]
        if honeypot.file(rel) or honeypot.request(path, ev.get("domain") or data.get("host")):
            mark_honeypot(ev)
    ev["host"] = name
    ev.setdefault("data", {})["log"] = rel
    return ev


class FileTail:
    """Reads what was added to one log file since the last read; follows logrotate (rename + new file, or copytruncate)."""

    def __init__(self, path: str, state: dict[str, Any] | None, backfill: int) -> None:
        self.path = path
        self.ino: int | None = (state or {}).get("ino")
        self.pos: int = int((state or {}).get("pos") or 0)
        self.new = state is None
        self.backfill = backfill
        self.lines = 0
        self.last_line: float | None = None
        self.error: str | None = None
        self.size = 0

    def state(self) -> dict[str, Any]:
        return {"ino": self.ino, "pos": self.pos}

    def _rotated(self) -> str | None:
        """The renamed old file (access.log.1) when it is the one read so far."""
        for cand in (self.path + ".1", self.path + ".0", self.path + "-1"):
            try:
                if os.stat(cand).st_ino == self.ino:
                    return cand
            except OSError:
                continue
        return None

    @staticmethod
    def _read(path: str, pos: int, limit: int) -> tuple[list[str], int]:
        """Complete lines from ``pos`` (at most ``limit`` bytes) and the position after the last complete line."""
        with open(path, "rb") as fh:
            fh.seek(pos)
            data = fh.read(limit)
        end = data.rfind(b"\n")
        if end < 0:
            return [], pos
        chunk = data[:end + 1]
        return chunk.decode("utf-8", errors="replace").splitlines(), pos + len(chunk)

    def read(self) -> list[str]:
        """New complete lines (blocking - run in a thread)."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self.error = "not found"
            return []
        except OSError as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return []
        self.size = st.st_size
        out: list[str] = []
        try:
            if self.new:  # first time: start near the end
                self.new = False
                self.ino = st.st_ino
                self.pos = max(0, st.st_size - self.backfill)
                if self.pos:
                    with open(self.path, "rb") as fh:  # skip the partial first line
                        fh.seek(self.pos)
                        fh.readline()
                        self.pos = fh.tell()
            elif st.st_ino != self.ino:  # rotated: finish the old file, then the new one from its start
                old = self._rotated() if self.ino is not None else None
                if old:
                    lines, _ = self._read(old, self.pos, CHUNK)
                    out.extend(lines)
                self.ino, self.pos = st.st_ino, 0
            elif st.st_size < self.pos:  # truncated in place (copytruncate)
                self.pos = 0
            if st.st_size > self.pos:
                lines, self.pos = self._read(self.path, self.pos, CHUNK)
                out.extend(lines)
            self.error = None
        except PermissionError:
            self.error = ("permission denied - the files must be readable for the user Looking Glass runs as "
                          "(chmod o+r, or the same PUID/PGID as SWAG)")
        except OSError as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        if out:
            self.lines += len(out)
            self.last_line = time.time()
        return out


class SwagReader:
    """Follows SWAG's logs while Settings › SWAG & CrowdSec › SWAG log folder is set."""

    def __init__(self, settings: Settings, put: Callable[[dict[str, Any]], None]) -> None:
        self.settings = settings
        self.put = put
        self.name = (settings.swag_name or "SWAG").strip() or "SWAG"
        self.root = settings.swag_log_dir.strip().rstrip("/")
        self.honeypot = Honeypot(settings.swag_honeypot)
        self.tails: dict[str, FileTail] = {}
        self.kinds: dict[str, str] = {}
        self.stored: dict[str, Any] = {}
        self.started = time.time()

    def tz(self) -> Any:
        try:
            return ZoneInfo(self.settings.timezone or "UTC")
        except Exception:  # noqa: BLE001
            return timezone.utc

    def patterns(self) -> list[tuple[str, str]]:
        s = self.settings
        out = [("access", p) for p in split_list(s.swag_access_logs)]
        out += [("error", p) for p in split_list(s.swag_error_logs)]
        if s.swag_fail2ban_log.strip():
            out.append(("fail2ban", s.swag_fail2ban_log.strip()))
        out += [("access", f) for f in self.honeypot.files if f.endswith(".log") and "error" not in f]
        return out

    def discover(self) -> dict[str, str]:
        """Relative path -> kind of every log file the settings name (wildcards resolved; rotated copies skipped)."""
        found: dict[str, str] = {}
        for kind, pat in self.patterns():
            pat = pat.lstrip("/")
            full = os.path.join(self.root, pat)
            paths = sorted(glob.glob(full)) if any(c in pat for c in "*?[") else [full]
            for p in paths:
                rel = os.path.relpath(p, self.root)
                if re.search(r"\.(\d+|gz|bz2|xz|zst)$", rel):
                    continue
                found.setdefault(rel, kind)
        return found

    async def run(self) -> None:
        self.stored = await db.kv_get(STATE_KEY) or {}
        saved = 0.0
        while True:
            await self.read_once()
            if time.monotonic() - saved > 15:
                await self.save()
                saved = time.monotonic()
            await asyncio.sleep(READ_EVERY)

    async def read_once(self) -> int:
        tz = self.tz()
        n = 0
        root_ok = os.path.isdir(self.root)
        files = self.discover() if root_ok else {}
        backfill = max(0, int(self.settings.swag_backfill_mb or 0)) * 1024 * 1024
        for rel, kind in files.items():
            tail = self.tails.get(rel)
            if tail is None:
                tail = self.tails[rel] = FileTail(os.path.join(self.root, rel), self.stored.get(rel), backfill)
                self.kinds[rel] = kind
            while True:
                lines = await asyncio.to_thread(tail.read)
                for line in lines:
                    try:
                        ev = parse_line(kind, line, rel, self.name, tz, self.honeypot)
                    except Exception:  # noqa: BLE001 - one odd line must not stop the rest
                        log.debug("unparseable SWAG line in %s: %r", rel, line[:300], exc_info=True)
                        continue
                    if ev:
                        self.put(ev)
                        n += 1
                if len(lines) < 1000 or n > 200_000:
                    break
                await asyncio.sleep(0)  # a large backlog: keep reading, but let the rest of the app run
        return n

    async def save(self) -> None:
        state = {rel: t.state() for rel, t in self.tails.items() if t.ino is not None}
        if state != self.stored:
            await db.kv_set(STATE_KEY, state)
            self.stored = state
        await db.set_snapshot(STATUS_KEY, self.status())

    def status(self) -> dict[str, Any]:
        root_ok = os.path.isdir(self.root)
        return {
            "dir": self.root, "dir_ok": root_ok, "name": self.name, "last": time.time(),
            "error": None if root_ok else (f"{self.root} does not exist in the Looking Glass container - mount SWAG's "
                                           "log folder there (read only)"),
            "files": {rel: {"kind": self.kinds.get(rel), "size": t.size, "pos": t.pos, "lines": t.lines,
                            "last_line": t.last_line, "error": t.error} for rel, t in sorted(self.tails.items())},
            "wanted": [p for _, p in self.patterns()],
        }


async def test_logs(settings: Settings) -> list[dict[str, Any]]:
    """Settings › SWAG & CrowdSec › Test connection: which configured logs exist and can be read."""
    if not settings.swag_enabled:
        return []
    reader = SwagReader(settings, lambda ev: None)
    if not os.path.isdir(reader.root):
        return [{"ok": False, "text": f"Log folder {reader.root} not found inside the Looking Glass container: add a "
                                      "read-only volume, e.g. /mnt/user/appdata/swag/log → /swag/log."}]
    files = reader.discover()
    out = []
    for kind, pat in reader.patterns():
        matched = [rel for rel, k in files.items() if fnmatch.fnmatch(rel, pat.lstrip("/"))]
        if not matched:
            out.append({"ok": False, "text": f"{pat} ({kind}): no file matches in {reader.root}"})
        for rel in matched:
            path = os.path.join(reader.root, rel)
            if not os.path.exists(path):
                out.append({"ok": False, "text": f"{rel} ({kind}): no such file in {reader.root} (yet)"})
                continue
            try:
                with open(path, "rb") as fh:
                    fh.seek(max(0, os.path.getsize(path) - 65536))
                    sample = fh.read().decode("utf-8", errors="replace").splitlines()[-50:]
                parsed = [parse_line(kind, ln, rel, reader.name, timezone.utc, reader.honeypot) for ln in sample]
                good = [e for e in parsed if e and (e.get("action") or kind == "error")]
                out.append({"ok": True, "text": f"{rel} ({kind}): readable, {os.path.getsize(path):,} bytes"
                                                + (f", {len(good)} of the last {len(sample)} lines understood" if sample else ", empty")})
            except PermissionError:
                out.append({"ok": False, "text": f"{rel}: permission denied - make it readable for Looking Glass's user (chmod o+r)"})
            except OSError as exc:
                out.append({"ok": False, "text": f"{rel}: {exc}"})
    return out
