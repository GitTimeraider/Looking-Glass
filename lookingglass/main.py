"""Entry point: starts the database, syslog receiver, OPNsense poller, detection engine and web UI."""
from __future__ import annotations

import asyncio
import logging
import secrets
import signal
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import uvicorn

from . import __version__, app_config, auth, crypto, db, db_config, notify
from .ai import Analyst
from .config import get_settings
from .detections import DetectionEngine, dhcp_listener, zenarmor_device_listener
from .enrich import Enricher
from .ingest import EventWriter, SyslogServer
from .opnsense import Poller
from .reports import build_report, run_ai_summary
from .unifi import UnifiPoller
from .unraid import UnraidManager
from .web.app import create_app
from .web.wizard import Wizard
from .zenarmor_es import create_es_app

log = logging.getLogger("lookingglass")


async def housekeeping(settings) -> None:
    """Retention: delete old events / metrics / closed alerts once per hour in small batches."""
    while True:
        try:
            pool = db.pool()
            # events claiming a time after they were received come from a wrong time zone: use the receive time
            # (once over all rows, then hourly for the newest ones)
            if not await db.kv_get("fixed_future_ts_v1"):
                fixed = await pool.execute("UPDATE events SET ts = received_at WHERE ts > received_at + interval '2 minutes'")
                await db.kv_set("fixed_future_ts_v1", True)
                log.info("time stamps after their receive time repaired: %s", fixed)
            else:
                await pool.execute("UPDATE events SET ts = received_at WHERE ts > now() + interval '2 minutes'")
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


async def opnsense_supervisor(settings, writer: EventWriter) -> None:
    """Run the OPNsense poller and restart it whenever its settings change in the web UI."""
    poller: Poller | None = None
    task: asyncio.Task | None = None
    sig = None
    announced = False
    while True:
        new_sig = app_config.signature(settings, "opnsense")
        if new_sig != sig or (task is not None and task.done()):
            if poller is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await poller.stop()
                poller = task = None
            sig = new_sig
            if settings.opnsense_enabled:
                poller = Poller(settings, writer)
                task = asyncio.create_task(poller.run(), name="poller")
                announced = False
            elif not announced:
                log.warning("OPNsense API not configured - set URL, API key and secret under Settings in the web UI")
                announced = True
        await asyncio.sleep(5)


async def unifi_supervisor(settings, writer: EventWriter) -> None:
    """Run the UniFi poller while it is configured; restart it whenever its settings change."""
    poller: UnifiPoller | None = None
    task: asyncio.Task | None = None
    sig = None
    while True:
        new_sig = app_config.signature(settings, "unifi")
        if new_sig != sig or (task is not None and task.done()):
            if poller is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await poller.stop()
                poller = task = None
            sig = new_sig
            if settings.unifi_enabled:
                poller = UnifiPoller(settings, writer)
                task = asyncio.create_task(poller.run(), name="unifi")
        await asyncio.sleep(5)


async def daily_ai_report(settings, analyst: Analyst) -> None:
    while True:
        await asyncio.sleep(300)
        if not settings.ai_daily_report:
            continue
        try:
            tz = ZoneInfo(settings.timezone or "UTC")
        except Exception:  # noqa: BLE001
            tz = timezone.utc
        now = datetime.now(tz)
        if now.hour != settings.ai_daily_report_hour:
            continue
        key = now.strftime("%Y-%m-%d")
        if await db.kv_get("daily_report") == key:
            continue
        await db.kv_set("daily_report", key)
        try:
            data = await build_report(24)
            rid = await db.pool().fetchval("INSERT INTO reports (period_h, title, data) VALUES (24, $1, $2) RETURNING id",
                                           f"Daily security report {key}", data)
            if settings.ai_enabled:
                await run_ai_summary(analyst, rid)  # a failure is stored with the report (Retry on its page)
            log.info("daily report %s created", key)
        except Exception:  # noqa: BLE001
            log.exception("daily report failed")


async def run_wizard(settings, need_db: bool, need_admin: bool, stop: asyncio.Event) -> bool:
    """Serve the first-start wizard until the database and the first account exist. False = shut down instead."""
    wizard = Wizard(settings, need_db, need_admin)
    server = uvicorn.Server(uvicorn.Config(wizard.app(), host=settings.web_host, port=settings.web_port,
                                           log_level="warning", proxy_headers=True, forwarded_allow_ips="*"))
    server.install_signal_handlers = lambda: None
    web = asyncio.create_task(server.serve(), name="wizard")
    waiters = [asyncio.create_task(wizard.done.wait()), asyncio.create_task(stop.wait())]
    await asyncio.wait([web, *waiters], return_when=asyncio.FIRST_COMPLETED)
    if wizard.done.is_set():
        await asyncio.sleep(1)  # let the browser receive the last answer
        log.info("setup complete")
    server.should_exit = True
    await asyncio.gather(web, return_exceptions=True)
    for w in waiters:
        w.cancel()
    return wizard.done.is_set()


async def amain() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    log.info("Looking Glass %s starting", __version__)
    try:
        crypto.init(settings.data_dir)
    except crypto.KeyFileError as exc:
        log.critical("%s", exc)
        raise SystemExit(2) from exc
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    # database: DATABASE_URL from the environment, else the connection saved by the setup wizard
    need_db = False
    if settings.database_url:
        await db.connect(settings.database_url)
    elif cfg := db_config.load(settings.data_dir):
        await db.connect(**db_config.connect_kwargs(cfg))
    else:
        need_db = True
    need_admin = not need_db and not await auth.ensure_admin(settings.admin_user, settings.admin_password)
    if (need_db or need_admin) and not await run_wizard(settings, need_db, need_admin, stop):
        await db.close()
        return
    await app_config.load(settings)
    if not settings.secret_key:
        # persist a generated cookie key so logins survive restarts
        settings.secret_key = await db.kv_get("secret_key") or secrets.token_urlsafe(48)
        await db.kv_set("secret_key", settings.secret_key)
    enricher = Enricher(settings)
    writer = EventWriter(enricher)
    writer.listeners.append(dhcp_listener)
    writer.listeners.append(zenarmor_device_listener)
    analyst = Analyst(settings)

    tasks = [asyncio.create_task(writer.run(), name="writer"),
             asyncio.create_task(DetectionEngine(settings).run(), name="detections"),
             asyncio.create_task(housekeeping(settings), name="housekeeping")]
    if settings.syslog_enabled:
        await SyslogServer(settings, writer).start()
    tasks.append(asyncio.create_task(opnsense_supervisor(settings, writer), name="opnsense"))
    tasks.append(asyncio.create_task(UnraidManager(settings, writer).run(), name="unraid"))
    tasks.append(asyncio.create_task(unifi_supervisor(settings, writer), name="unifi"))
    tasks.append(asyncio.create_task(daily_ai_report(settings, analyst), name="daily_report"))
    tasks.append(asyncio.create_task(notify.notifier(settings), name="notifier"))
    from .intel import Intel
    tasks.append(asyncio.create_task(Intel(settings).updater(), name="threat_feeds"))

    app = create_app(settings, analyst)
    server = uvicorn.Server(uvicorn.Config(app, host=settings.web_host, port=settings.web_port, log_level="warning",
                                           proxy_headers=True, forwarded_allow_ips="*"))
    server.install_signal_handlers = lambda: None  # we handle signals ourselves

    web = asyncio.create_task(server.serve(), name="web")
    es_server = None
    if settings.zenarmor_es_port:
        es_server = uvicorn.Server(uvicorn.Config(create_es_app(settings, writer), host=settings.web_host,
                                                  port=settings.zenarmor_es_port, log_level="warning"))
        es_server.install_signal_handlers = lambda: None
        tasks.append(asyncio.create_task(es_server.serve(), name="zenarmor-es"))
        log.info("Zenarmor Elasticsearch-compatible receiver on port %s", settings.zenarmor_es_port)
    log.info("web UI on http://%s:%s", settings.web_host, settings.web_port)
    done, _ = await asyncio.wait([web, asyncio.create_task(stop.wait()), *tasks], return_when=asyncio.FIRST_COMPLETED)
    for t in done:
        if t.exception() if not t.cancelled() else None:
            log.error("task %s died: %r", t.get_name(), t.exception())
    server.should_exit = True
    if es_server:
        es_server.should_exit = True
    for t in tasks:
        t.cancel()
    await asyncio.gather(web, return_exceptions=True)
    await db.close()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
