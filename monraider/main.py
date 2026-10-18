"""Entry point: starts the database, syslog receiver, OPNsense poller, detection engine and web UI."""
from __future__ import annotations

import asyncio
import logging
import secrets
import signal
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import uvicorn

from . import __version__, db
from .ai import Analyst
from .config import get_settings
from .detections import DetectionEngine, dhcp_listener
from .enrich import Enricher
from .ingest import EventWriter, SyslogServer
from .opnsense import Poller
from .reports import build_report
from .web.app import create_app

log = logging.getLogger("monraider")


async def housekeeping(settings) -> None:
    """Retention: delete old events / metrics / closed alerts once per hour in small batches."""
    while True:
        try:
            pool = db.pool()
            while True:
                status = await pool.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < now() - make_interval(days => $1) LIMIT 50000)",
                    settings.retention_days)
                if int(status.split()[-1]) < 50000:
                    break
                await asyncio.sleep(0.5)
            await pool.execute("DELETE FROM metrics WHERE ts < now() - make_interval(days => $1)", settings.metrics_retention_days)
            await pool.execute("DELETE FROM alerts WHERE status = 'closed' AND last_seen < now() - make_interval(days => $1)",
                               max(settings.retention_days, 90))
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")
        await asyncio.sleep(3600)


async def daily_ai_report(settings, analyst: Analyst) -> None:
    try:
        tz = ZoneInfo(settings.timezone)
    except Exception:  # noqa: BLE001
        tz = timezone.utc
    while True:
        await asyncio.sleep(300)
        now = datetime.now(tz)
        if now.hour != settings.ai_daily_report_hour:
            continue
        key = now.strftime("%Y-%m-%d")
        if await db.kv_get("daily_report") == key:
            continue
        await db.kv_set("daily_report", key)
        try:
            data = await build_report(24)
            summary = await analyst.analyse(24) if settings.ai_enabled else None
            await db.pool().execute("INSERT INTO reports (period_h, title, data, ai_summary) VALUES (24, $1, $2, $3)",
                                    f"Daily security report {key}", data, summary)
            log.info("daily report %s created", key)
        except Exception:  # noqa: BLE001
            log.exception("daily report failed")


async def amain() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    log.info("MonRaider %s starting", __version__)
    if not settings.admin_password:
        settings.admin_password = secrets.token_urlsafe(12)
        log.warning("ADMIN_PASSWORD not set - generated one for this run: user=%s password=%s",
                    settings.admin_user, settings.admin_password)

    await db.connect(settings.database_url)
    enricher = Enricher(settings.geoip_db, settings.internal_networks)
    writer = EventWriter(enricher)
    writer.listeners.append(dhcp_listener)
    analyst = Analyst(settings)

    tasks = [asyncio.create_task(writer.run(), name="writer"),
             asyncio.create_task(DetectionEngine(settings).run(), name="detections"),
             asyncio.create_task(housekeeping(settings), name="housekeeping")]
    if settings.syslog_enabled:
        await SyslogServer(settings, writer).start()
    if settings.opnsense_enabled:
        tasks.append(asyncio.create_task(Poller(settings, writer).run(), name="poller"))
    else:
        log.warning("OPNSENSE_URL / OPNSENSE_API_KEY / OPNSENSE_API_SECRET not set - API polling disabled")
    if settings.ai_daily_report:
        tasks.append(asyncio.create_task(daily_ai_report(settings, analyst), name="daily_report"))

    app = create_app(settings, analyst)
    server = uvicorn.Server(uvicorn.Config(app, host=settings.web_host, port=settings.web_port, log_level="warning",
                                           proxy_headers=True, forwarded_allow_ips="*"))
    server.install_signal_handlers = lambda: None  # we handle signals ourselves
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    web = asyncio.create_task(server.serve(), name="web")
    log.info("web UI on http://%s:%s", settings.web_host, settings.web_port)
    done, _ = await asyncio.wait([web, asyncio.create_task(stop.wait()), *tasks], return_when=asyncio.FIRST_COMPLETED)
    for t in done:
        if t.exception() if not t.cancelled() else None:
            log.error("task %s died: %r", t.get_name(), t.exception())
    server.should_exit = True
    for t in tasks:
        t.cancel()
    await asyncio.gather(web, return_exceptions=True)
    await db.close()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
