import asyncio
import os
from datetime import datetime, timezone

import pytest

from lookingglass import app_config, dashboards, db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine
from lookingglass.parsers.security import suricata_from_eve

DSN = os.environ.get("TEST_DATABASE_URL")


def test_ignore_sids_validation():
    f = app_config.BY_KEY["ids_ignore_sids"]
    assert app_config._coerce(f, "2210050\n123") == "2210050, 123"
    with pytest.raises(app_config.SettingsError):
        app_config._coerce(f, "not-a-sid")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_ids_alert_priority_ignored_sids_and_tls():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            evs = [suricata_from_eve({"timestamp": now.isoformat(), "event_type": "alert", "src_ip": "203.0.113.5",
                                      "dest_ip": "192.168.1.10", "alert": {"signature": sig, "signature_id": sid, "severity": prio}}, now)
                   for sig, sid, prio in (("P1", 1, 1), ("P3", 3, 3), ("Ignored", 2210050, 1))]
            evs.append(suricata_from_eve({"timestamp": now.isoformat(), "event_type": "tls", "src_ip": "192.168.1.20",
                                          "dest_ip": "198.51.100.7", "tls": {"sni": "example.com"}}, now))
            for e in evs:
                await pool.execute("INSERT INTO events (ts, source, severity, action, src_ip, dst_ip, message, domain, data) "
                                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", e["ts"], e["source"], e.get("severity"),
                                   e.get("action"), e.get("src_ip"), e.get("dst_ip"), e.get("message"), e.get("domain"), e.get("data"))
            await DetectionEngine(Settings(ids_alert_priority=2, ids_ignore_sids="2210050")).ids_alerts()
            assert [r["title"] for r in await pool.fetch("SELECT title FROM alerts")] == ["Suricata: P1"]
            out = await dashboards.run_dashboard("suricata", 24)
            assert not [p for p in out["panels"] if "error" in p]
            kpi = next(p for p in out["panels"] if p["id"] == "kpi")["rows"][0]
            assert kpi["Alerts"] == 3 and kpi["TLS records"] == 1
        finally:
            await db.close()

    asyncio.run(main())
