"""Syslog listeners (UDP + TCP) and the batched event writer."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from datetime import timezone
from typing import Any
from zoneinfo import ZoneInfo

from . import db
from .config import Settings
from .enrich import Enricher
from .parsers import parse_line
from .parsers.common import parse_networks

log = logging.getLogger(__name__)


class Stats:
    def __init__(self) -> None:
        self.received = 0
        self.parsed = 0
        self.dropped = 0
        self.written = 0
        self.errors = 0
        self.by_source: dict[str, int] = {}
        self.last_by_source: dict[str, float] = {}
        self.senders: dict[str, float] = {}
        self.extra: dict[str, Any] = {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "received": self.received, "parsed": self.parsed, "dropped": self.dropped,
            "written": self.written, "errors": self.errors, "by_source": self.by_source,
            "last_by_source": self.last_by_source, "senders": self.senders, **self.extra,
        }


STATS = Stats()


class EventWriter:
    """Collects events from all producers and writes them to PostgreSQL in batches."""

    def __init__(self, enricher: Enricher, max_queue: int = 200_000, batch: int = 2000, flush_s: float = 1.0) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue)
        self.enricher = enricher
        self.batch = batch
        self.flush_s = flush_s
        self.listeners: list = []  # callables invoked with each written event (e.g. device tracker)

    def put(self, ev: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:
            STATS.dropped += 1

    async def run(self) -> None:
        while True:
            first = await self.queue.get()
            items = [first]
            deadline = time.monotonic() + self.flush_s
            while len(items) < self.batch:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    items.append(await asyncio.wait_for(self.queue.get(), timeout))
                except asyncio.TimeoutError:
                    break
            await self._write(items)

    async def _write(self, items: list[dict[str, Any]]) -> None:
        for ev in items:
            self.enricher.enrich(ev)
        plain = [e for e in items if not e.get("uid")]
        dedup = [e for e in items if e.get("uid")]
        try:
            await db.copy_events(plain)
            n = await db.insert_events_dedup(dedup)
            STATS.written += len(plain) + n
        except Exception:  # noqa: BLE001 - keep ingest alive, log and try rows one by one
            log.exception("batch insert failed, retrying row by row")
            for ev in plain:
                try:
                    await db.copy_events([ev])
                    STATS.written += 1
                except Exception as exc:  # noqa: BLE001
                    STATS.errors += 1
                    log.warning("dropping unwritable event %s: %s", ev.get("message", "")[:200], exc)
        for cb in self.listeners:
            try:
                await cb(items)
            except Exception:  # noqa: BLE001
                log.exception("event listener failed")


class SyslogServer:
    def __init__(self, settings: Settings, writer: EventWriter) -> None:
        self.settings = settings
        self.writer = writer
        self._tz_name: str | None = None
        self._tz: Any = timezone.utc

    @property
    def tz(self):
        # settings can change at runtime (web UI) - resolve lazily
        if self.settings.timezone != self._tz_name:
            self._tz_name = self.settings.timezone
            try:
                self._tz = ZoneInfo(self._tz_name or "UTC")
            except Exception:  # noqa: BLE001
                self._tz = timezone.utc
        return self._tz

    def _allowed(self, addr: str) -> bool:
        allowed = parse_networks(self.settings.syslog_allowed_senders)
        if not allowed:
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in n for n in allowed)

    def handle(self, line: str, sender: str) -> None:
        STATS.received += 1
        STATS.senders[sender] = time.time()
        if not self._allowed(sender):
            STATS.dropped += 1
            return
        try:
            ev = parse_line(line, sender=sender, local_tz=self.tz)
        except Exception:  # noqa: BLE001
            STATS.errors += 1
            log.debug("unparseable line from %s: %r", sender, line[:500], exc_info=True)
            return
        if ev is None:
            return
        STATS.parsed += 1
        src = ev["source"]
        STATS.by_source[src] = STATS.by_source.get(src, 0) + 1
        STATS.last_by_source[src] = time.time()
        self.writer.put(ev)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        server = self

        class UDP(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
                text = data.decode("utf-8", errors="replace")
                # one datagram normally carries one message, some senders batch with newlines
                for line in text.split("\n") if "\n<" in text else [text]:
                    server.handle(line, addr[0])

        await loop.create_datagram_endpoint(UDP, local_addr=(self.settings.syslog_host, self.settings.syslog_udp_port))
        log.info("syslog UDP listening on %s:%s", self.settings.syslog_host, self.settings.syslog_udp_port)
        await asyncio.start_server(self._tcp_client, self.settings.syslog_host, self.settings.syslog_tcp_port, limit=1 << 20)
        log.info("syslog TCP listening on %s:%s", self.settings.syslog_host, self.settings.syslog_tcp_port)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sender = peer[0] if peer else "?"
        try:
            while True:
                first = await reader.read(1)
                if not first:
                    break
                if first.isdigit():
                    # RFC 6587 octet counting: "<len> <msg>"
                    head = first + await reader.readuntil(b" ")
                    try:
                        length = int(head.strip())
                        data = await reader.readexactly(length)
                    except ValueError:
                        data = head + await reader.readuntil(b"\n")
                else:
                    # non-transparent framing, newline terminated
                    data = first + await reader.readuntil(b"\n")
                self.handle(data.decode("utf-8", errors="replace"), sender)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
