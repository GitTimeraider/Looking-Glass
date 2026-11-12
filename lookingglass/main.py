"""Entry point: starts the database, syslog receiver, OPNsense poller, detection engine and web UI."""
from __future__ import annotations

import asyncio
import logging
import secrets
import signal
import socket
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import uvicorn

from . import __version__, app_config, auth, crypto, db, db_config, notify, optional_sources, rollup
from .ai import Analyst, request_log
from .backrest import BackrestPoller
from .config import get_settings
from .detections import (
    DetectionEngine,
    device_upkeep,
    dhcp_listener,
    zenarmor_device_listener,
)
from .enrich import Enricher
from .ingest import EventWriter, SyslogServer
from .opnsense import Poller
from .reports import build_report, report_due, report_mail, run_ai_summary
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
            await rollup.prune(settings.retention_days)
            await pool.execute("DELETE FROM metrics WHERE ts < now() - make_interval(days => $1)", settings.metrics_retention_days)
            await pool.execute("DELETE FROM backup_runs WHERE started < now() - interval '400 days'")
            await pool.execute("DELETE FROM backup_runs_removed WHERE removed_at < now() - interval '400 days'")
            await pool.execute("DELETE FROM alerts WHERE status = 'closed' AND last_seen < now() - make_interval(days => $1)",
                               max(settings.retention_days, 90))
            # comments of alerts that are gone (deleted here, by hand or with an older version)
            await pool.execute("DELETE FROM alert_comments c WHERE NOT EXISTS (SELECT 1 FROM alerts a WHERE a.id = c.alert_id)")
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")
        await asyncio.sleep(3600)


async def device_upkeep_loop(settings) -> None:
    """Every minute: quiet clients without a MAC -> offline, and the device removal of Settings › Data & detection."""
    while True:
        await asyncio.sleep(60)
        try:
            await device_upkeep(settings.device_remove_days)
        except Exception:  # noqa: BLE001
            log.exception("device upkeep failed")


async def _stop_poller(poller, task: asyncio.Task | None) -> None:
    """Stop a poller's main loop and its running jobs - also while the caller itself is being cancelled (shutdown)."""
    async def stop() -> None:
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        try:
            await poller.stop()
        except Exception:  # noqa: BLE001
            log.exception("stopping a poller failed")
    await asyncio.shield(stop())


async def keep_running(name: str, factory, once: bool = False) -> None:
    """Run a background loop for as long as Looking Glass runs. One that crashes (e.g. a database query failed while
    the database was overloaded or restarting) is restarted after a pause instead of shutting the whole app down.
    ``once``: a job that is finished when it returns (e.g. building the dashboard indexes); only a crash restarts it.
    Either way this never returns by itself: its end would stop Looking Glass (main waits for the first task to end)."""
    delay = 10
    while True:
        started = asyncio.get_running_loop().time()
        try:
            await factory()
            if once:
                log.debug("background job %s done", name)
                await asyncio.Event().wait()  # done: stays idle until shutdown
            problem, error = "stopped unexpectedly", None
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            problem, error = "crashed", exc
        if asyncio.get_running_loop().time() - started > 600:
            delay = 10  # it ran fine for a while: the next problem starts with a short pause again
        log.error("background task %s %s, restarting it in %ss", name, problem, delay, exc_info=error)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 300)


async def opnsense_supervisor(settings, writer: EventWriter) -> None:
    """Run the OPNsense poller and restart it whenever its settings change in the web UI."""
    poller: Poller | None = None
    task: asyncio.Task | None = None
    sig = None
    announced = False
    try:
        while True:
            new_sig = app_config.signature(settings, "opnsense")
            if new_sig != sig or (task is not None and task.done()):
                if poller is not None:
                    await _stop_poller(poller, task)
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
    finally:  # shutdown: its jobs must not go on writing into the closing database
        if poller is not None:
            await _stop_poller(poller, task)


async def unifi_supervisor(settings, writer: EventWriter) -> None:
    """Run the UniFi poller while it is configured; restart it whenever its settings change."""
    poller: UnifiPoller | None = None
    task: asyncio.Task | None = None
    sig = None
    try:
        while True:
            new_sig = app_config.signature(settings, "unifi")
            if new_sig != sig or (task is not None and task.done()):
                if poller is not None:
                    await _stop_poller(poller, task)
                    poller = task = None
                sig = new_sig
                if settings.unifi_enabled:
                    poller = UnifiPoller(settings, writer)
                    task = asyncio.create_task(poller.run(), name="unifi")
            await asyncio.sleep(5)
    finally:  # shutdown: its jobs must not go on writing into the closing database
        if poller is not None:
            await _stop_poller(poller, task)


async def backrest_supervisor(settings) -> None:
    """Run the Backrest poller while it is configured; restart it whenever its settings change."""
    poller: BackrestPoller | None = None
    task: asyncio.Task | None = None
    sig = None
    try:
        while True:
            new_sig = app_config.signature(settings, "backrest")
            if new_sig != sig or (task is not None and task.done()):
                if poller is not None:
                    await _stop_poller(poller, task)
                    poller = task = None
                sig = new_sig
                if settings.backrest_enabled:
                    poller = BackrestPoller(settings)
                    task = asyncio.create_task(poller.run(), name="backrest")
            await asyncio.sleep(5)
    finally:  # shutdown: its jobs must not go on writing into the closing database
        if poller is not None:
            await _stop_poller(poller, task)


def _listen(host: str, port: int) -> socket.socket:
    """The receiver's listening socket, opened here so a port that cannot be opened is a normal error (uvicorn would
    end the whole program)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


ES_CHECK_S = 5  # how often the Zenarmor receiver follows its switch


async def zenarmor_es_supervisor(settings, writer: EventWriter) -> None:
    """The Zenarmor Elasticsearch receiver: its port is open only while Zenarmor is switched on (Settings › OPNsense ›
    Receive Zenarmor data) and ZENARMOR_ES_PORT is not 0. Switching it off closes the port within a few seconds,
    switching it on opens it again - no restart needed."""
    server: uvicorn.Server | None = None
    task: asyncio.Task | None = None
    retry_at = 0.0
    loop = asyncio.get_running_loop()

    async def stop() -> None:
        nonlocal server, task
        if server is not None:
            server.should_exit = True
            await asyncio.gather(task, return_exceptions=True)
        server = task = None

    try:
        while True:
            want = bool(settings.zenarmor_enabled and settings.zenarmor_es_port)
            if task is not None and task.done():
                log.error("Zenarmor receiver stopped (%r), opening it again in 30s",
                          None if task.cancelled() else task.exception())
                server = task = None
                retry_at = loop.time() + 30
            if want and server is None and loop.time() >= retry_at:
                try:
                    sock = _listen(settings.web_host, settings.zenarmor_es_port)
                except OSError as exc:
                    log.error("Zenarmor receiver: port %s cannot be opened (%s), trying again in 30s",
                              settings.zenarmor_es_port, exc)
                    retry_at = loop.time() + 30
                else:
                    server = uvicorn.Server(uvicorn.Config(create_es_app(settings, writer), log_level="warning",
                                                           lifespan="off"))
                    server.install_signal_handlers = lambda: None
                    task = asyncio.create_task(server.serve(sockets=[sock]), name="zenarmor-es")
                    log.info("Zenarmor Elasticsearch-compatible receiver on port %s", settings.zenarmor_es_port)
            elif not want and server is not None:
                await stop()
                log.info("Zenarmor switched off: receiver port %s closed", settings.zenarmor_es_port)
            await asyncio.sleep(ES_CHECK_S)
    finally:
        await stop()


async def daily_ai_report(settings, analyst: Analyst) -> None:
    """The scheduled report: every ``report_every_days`` days at the set hour, covering those days; mailed when
    recipients are set."""
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
        every = max(1, settings.report_every_days)
        title = f"Daily security report {key}" if every == 1 else f"Security report {key} ({every} days)"
        try:
            if not report_due(await db.kv_get("daily_report"), now.date(), every):
                continue
            await db.kv_set("daily_report", key)
            data = await build_report(24 * every)
            rid = await db.pool().fetchval("INSERT INTO reports (period_h, title, data) VALUES ($1, $2, $3) RETURNING id",
                                           24 * every, title, data)
            if settings.ai_enabled:
                request_log.info("scheduled report %s: starting the AI analysis", key)
                await run_ai_summary(analyst, rid)  # a failure is stored with the report (Retry on its page)
            log.info("scheduled report %s created", key)
        except Exception:  # noqa: BLE001
            log.exception("scheduled report failed")
            continue
        if settings.report_mail_to and settings.smtp_enabled:
            try:
                subject, text, body = await report_mail(rid, settings.mail_link_url or settings.public_url)
                await notify.send(settings, notify.recipients(settings.report_mail_to), subject, text, body)
                log.info("scheduled report %s mailed", key)
            except Exception:  # noqa: BLE001
                log.exception("mailing the scheduled report failed")


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
    request_log.setLevel(logging.INFO if settings.log_ai_requests else logging.WARNING)
    log.info("Looking Glass %s starting", __version__)
    try:
        crypto.init(settings.data_dir)
    except crypto.KeyFileError as exc:
        log.critical("%s", exc)
        raise SystemExit(2) from exc
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def on_signal(sig: signal.Signals) -> None:
        log.warning("%s received (container stopped or restarted from outside): shutting down", sig.name)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, on_signal, sig)

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
    from .packages import PackageReader
    if not settings.secret_key:
        # persist a generated cookie key so logins survive restarts
        settings.secret_key = await db.kv_get("secret_key") or secrets.token_urlsafe(48)
        await db.kv_set("secret_key", settings.secret_key)
    enricher = Enricher(settings)
    writer = EventWriter(enricher)
    writer.listeners.append(dhcp_listener)
    writer.listeners.append(zenarmor_device_listener)
    writer.listeners.append(optional_sources.listener)
    try:  # before the web UI starts: the menu shows Zenarmor only when it is set up
        await optional_sources.refresh()
    except Exception:  # noqa: BLE001
        log.exception("checking whether Zenarmor is set up failed")
    analyst = Analyst(settings)

    tasks: list[asyncio.Task] = []

    def background(name: str, factory, once: bool = False) -> None:
        """A loop that runs as long as Looking Glass does (restarted when it crashes, see keep_running)."""
        tasks.append(asyncio.create_task(keep_running(name, factory, once), name=name))

    detections = DetectionEngine(settings)
    background("writer", writer.run)
    background("detections", detections.run)
    background("housekeeping", lambda: housekeeping(settings))
    background("event_rollup", rollup.loop)
    background("dashboard_indexes", db.background_indexes_loop, once=True)
    background("device_upkeep", lambda: device_upkeep_loop(settings))
    background("optional_sources", optional_sources.loop)
    if settings.syslog_enabled:
        await SyslogServer(settings, writer).start()
    background("opnsense", lambda: opnsense_supervisor(settings, writer))
    unraid = UnraidManager(settings, writer)
    background("unraid", unraid.run)
    background("unifi", lambda: unifi_supervisor(settings, writer))
    background("backrest", lambda: backrest_supervisor(settings))
    background("zenarmor_es", lambda: zenarmor_es_supervisor(settings, writer))
    background("daily_report", lambda: daily_ai_report(settings, analyst))
    background("notifier", lambda: notify.notifier(settings))
    from .intel import Intel
    intel = Intel(settings)
    background("threat_feeds", intel.updater)
    packages = PackageReader(settings)
    background("container_packages", packages.run)

    app = create_app(settings, analyst)
    app.state.packages = packages
    background("long_periods", app.state.periods.run)  # 7 / 30 day views, counted on a schedule (periods.py)
    server = uvicorn.Server(uvicorn.Config(app, host=settings.web_host, port=settings.web_port, log_level="warning",
                                           proxy_headers=True, forwarded_allow_ips="*"))
    server.install_signal_handlers = lambda: None  # we handle signals ourselves

    web = asyncio.create_task(server.serve(), name="web")
    servers = [web]  # web servers are stopped with should_exit: cancelling one logs a CancelledError traceback
    log.info("web UI on http://%s:%s", settings.web_host, settings.web_port)
    done, _ = await asyncio.wait([*servers, asyncio.create_task(stop.wait()), *tasks], return_when=asyncio.FIRST_COMPLETED)
    for t in done:  # why Looking Glass stops (a signal is logged by on_signal)
        if t in servers or t in tasks:
            exc = t.exception() if not t.cancelled() else None
            log.error("%s stopped%s: shutting down", t.get_name(), f" ({exc!r})" if exc else "")
    server.should_exit = True
    for t in tasks:
        t.cancel()
    await asyncio.gather(*servers, *tasks, return_exceptions=True)
    await db.close()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
