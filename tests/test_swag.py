"""SWAG logs (swag.py, parsers/fail2ban.py, the CrowdSec bouncer lines in parsers/nginx.py) and CrowdSec's Local API
(crowdsec_lapi.py)."""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from lookingglass import crowdsec_lapi as lapi
from lookingglass.parsers import fail2ban, nginx
from lookingglass.swag import FileTail, Honeypot, parse_line

AMS = ZoneInfo("Europe/Amsterdam")
NOW = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------------------------------------- fail2ban ---
def test_fail2ban_ban_found_unban():
    ev = fail2ban.parse("2024-05-01 14:00:01,456 fail2ban.actions        [512]: NOTICE  [nginx-http-auth] Ban 1.2.3.4", AMS, "SWAG")
    assert ev["source"] == "fail2ban" and ev["action"] == "ban" and ev["src_ip"] == "1.2.3.4"
    assert ev["data"]["jail"] == "nginx-http-auth" and ev["host"] == "SWAG"
    assert ev["ts"] == datetime(2024, 5, 1, 12, 0, 1, 456000, tzinfo=timezone.utc)  # local time of the container
    found = fail2ban.parse("2024-05-01 12:00:00,123 fail2ban.filter  [512]: INFO    [sshd] Found 2001:db8::1 - 2024-05-01 12:00:00")
    assert found["action"] == "found" and found["src_ip"] == "2001:db8::1" and found["data"]["matched_at"].startswith("2024")
    assert fail2ban.parse("2024-05-01 12:10:01,456 fail2ban.actions [512]: NOTICE  [sshd] Unban 1.2.3.4")["action"] == "unban"
    assert fail2ban.parse("2024-05-01 12:10:01,456 fail2ban.actions [512]: NOTICE  [sshd] Restore Ban 1.2.3.4")["action"] == "restore_ban"
    already = fail2ban.parse("2024-05-01 12:10:01,456 fail2ban.actions [512]: WARNING [sshd] 1.2.3.4 already banned")
    assert already["action"] == "already_banned" and already["src_ip"] == "1.2.3.4"
    start = fail2ban.parse("2024-05-01 12:00:00,001 fail2ban.jail    [512]: INFO    Jail 'nginx-badbots' started")
    assert start["action"] == "jail_start" and start["data"]["jail"] == "nginx-badbots"
    assert fail2ban.parse("   continuation line") is None


def test_fail2ban_honeypot_jail():
    ev = fail2ban.parse("2024-05-01 12:00:01,456 fail2ban.actions [1]: NOTICE  [nginx-honeypot] Ban 1.2.3.4")
    assert ev["data"]["honeypot"] is True
    ev = fail2ban.parse("2024-05-01 12:00:01,456 fail2ban.actions [1]: NOTICE  [trap] Ban 1.2.3.4", honeypot_jails=frozenset({"trap"}))
    assert ev["data"]["honeypot"] is True
    ev = fail2ban.parse("2024-05-01 12:00:01,456 fail2ban.actions [1]: NOTICE  [sshd] Ban 1.2.3.4")
    assert "honeypot" not in ev["data"]


# ------------------------------------------------------------------------------- nginx: CrowdSec bouncer ---
def test_crowdsec_bouncer_and_appsec_lines():
    line = ("2024/05/01 12:00:00 [alert] 312#312: *9912 [lua] crowdsec.lua:612: Allow(): [Crowdsec] denied '45.148.10.81' "
            "with 'ban', client: 45.148.10.81, server: _, request: \"GET /.env HTTP/1.1\", host: \"cloud.example.com\"")
    ev = nginx.parse(NOW, "swag", "nginx-error", line)
    assert ev["action"] == "bouncer_block" and ev["src_ip"] == "45.148.10.81" and ev["severity"] == 4
    assert ev["domain"] == "cloud.example.com"  # server "_": the Host header names the site
    assert ev["data"]["remediation"] == "ban" and ev["data"]["blocked_by"] == "crowdsec"
    ev = nginx.parse(NOW, "swag", "nginx-error", line.replace("with 'ban'", "with 'ban' (by appsec)"))
    assert ev["action"] == "waf_block" and ev["data"]["by"] == "appsec"


# ------------------------------------------------------------------------------------------------ honeypot ---
def test_honeypot_spec():
    hp = Honeypot("/wp-login.php\n/secret*/x\nhoneypot.example.com\njail:my-trap\nfile:nginx/trap.log")
    assert hp.request("/wp-login.php?redirect=1", None)
    assert hp.request("/wp-login.php.bak", None)  # without a wildcard: a prefix
    assert not hp.request("/wp-admin", None)
    assert hp.request("/secret-area/x", None) and not hp.request("/secret-area/y", None)
    assert hp.request("/", "Honeypot.example.com:443")
    assert hp.jails == {"my-trap"}
    assert hp.file("nginx/trap.log") and hp.file("nginx/honeypot.access.log") and not hp.file("nginx/access.log")


def test_parse_line_access_error_fail2ban():
    hp = Honeypot("/trap")
    ev = parse_line("access", '1.2.3.4 - - [01/May/2024:14:00:00 +0200] "GET /trap/x HTTP/1.1" 200 5 "-" "curl/8"',
                    "nginx/access.log", "SWAG", AMS, hp, NOW)
    assert ev["source"] == "nginx" and ev["program"] == "swag" and ev["host"] == "SWAG"
    assert ev["data"]["honeypot"] is True and "honeypot" in ev["data"]["tags"] and ev["data"]["log"] == "nginx/access.log"
    assert ev["ts"] == NOW
    err = parse_line("error", '2024/05/01 14:00:00 [error] 1#1: *2 limiting requests, excess: 10.5 by zone "one", client: 5.6.7.8, '
                     'server: blog.example.com, request: "POST /wp-login.php HTTP/1.1", host: "blog.example.com"',
                     "nginx/error.log", "SWAG", AMS, hp, NOW + timedelta(hours=1))
    assert err["action"] == "rate_limited" and err["ts"] == NOW and err["program"] == "swag"  # error log: local time
    f = parse_line("fail2ban", "2024-05-01 14:00:01,000 fail2ban.actions [1]: NOTICE  [sshd] Ban 9.9.9.9",
                   "fail2ban/fail2ban.log", "SWAG", AMS, hp)
    assert f["source"] == "fail2ban" and f["host"] == "SWAG"
    assert parse_line("access", "   ", "nginx/access.log", "SWAG", AMS, hp) is None


# ------------------------------------------------------------------------------------------------ FileTail ---
def test_file_tail_backfill_append_partial_and_rotation(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("".join(f"line {i}\n" for i in range(100)))
    t = FileTail(str(log), None, backfill=30)  # first read: only the end, from a whole line on
    first = t.read()
    assert first and first[-1] == "line 99" and "line 0" not in first and all(x.startswith("line ") for x in first)
    assert t.read() == []
    with open(log, "a") as fh:
        fh.write("line 100\nline 1")  # the second line is still being written
    assert t.read() == ["line 100"]
    with open(log, "a") as fh:
        fh.write("01\n")
    assert t.read() == ["line 101"]
    # logrotate: rename + new file; lines written to the old file before the rename are not lost
    with open(log, "a") as fh:
        fh.write("last old line\n")
    os.rename(log, tmp_path / "access.log.1")
    log.write_text("first new line\n")
    assert t.read() == ["last old line", "first new line"]
    # copytruncate: the same file, shorter
    log.write_text("")
    assert t.read() == []
    log.write_text("after truncate\n")
    assert t.read() == ["after truncate"]
    # a restart continues where it was
    state = t.state()
    with open(log, "a") as fh:
        fh.write("while stopped\n")
    assert FileTail(str(log), state, backfill=10 ** 6).read() == ["while stopped"]


def test_file_tail_missing_file(tmp_path):
    t = FileTail(str(tmp_path / "nope.log"), None, 100)
    assert t.read() == [] and t.error == "not found"


# ---------------------------------------------------------------------------------------- CrowdSec LAPI ---
ALERT = {
    "id": 7, "uuid": "u-7", "machine_id": "crowdsec", "scenario": "crowdsecurity/vpatch-CVE-2023-22515", "events_count": 1,
    "start_at": "2024-05-01T12:00:00.123456789Z", "created_at": "2024-05-01T12:00:03Z",
    "source": {"scope": "Ip", "value": "194.26.29.102", "ip": "194.26.29.102", "cn": "SC", "as_name": "Unmanaged Ltd",
               "range": "194.26.29.0/24"},
    "events": [{"timestamp": "2024-05-01T12:00:00Z", "meta": [{"key": "target_fqdn", "value": "wiki.example.com"},
                                                              {"key": "target_uri", "value": "/server-info.action"},
                                                              {"key": "ignored_key", "value": "x"}]}],
    "decisions": [{"id": 31, "origin": "crowdsec", "type": "ban", "scope": "Ip", "value": "194.26.29.102",
                   "duration": "3h59m", "until": "2099-01-01T00:00:00Z"},
                  {"id": 32, "origin": "crowdsec", "type": "captcha", "scope": "Ip", "value": "194.26.29.102",
                   "duration": "1h", "until": "2000-01-01T00:00:00Z"}],
}


def test_lapi_times_with_nanoseconds():
    assert lapi._ts("2024-05-01T12:00:00.123456789Z") == datetime(2024, 5, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert lapi._ts("0001-01-01T00:00:00Z") is None and lapi._ts("") is None


def test_lapi_alert_events():
    evs = lapi.alert_events(ALERT)
    alert, ban, captcha = evs
    assert alert["action"] == "alert" and alert["uid"] == "csl-alert:u-7" and alert["program"] == "crowdsec-lapi"
    assert alert["src_ip"] == "194.26.29.102" and alert["src_country"] == "SC" and alert["domain"] == "wiki.example.com"
    assert alert["data"]["appsec"] is True and alert["data"]["as"] == "Unmanaged Ltd"
    assert alert["data"]["meta"] == {"target_fqdn": ["wiki.example.com"], "target_uri": ["/server-info.action"]}
    assert ban["action"] == "ban" and ban["uid"] == "csl-dec:31" and captcha["action"] == "captcha"
    assert lapi.alert_events(ALERT, seen={"a:u-7", "d:31", "d:32"}) == []
    active = lapi.active_from_alerts([ALERT])  # the expired captcha is not active
    assert [d["id"] for d in active] == [31] and active[0]["country"] == "SC"


def test_lapi_metrics_summary():
    s = lapi.metrics_summary("\n".join([
        'cs_info{version="v1.6.4"} 1',
        'cs_filesource_hits_total{source="/var/log/swag/nginx/access.log",type="file"} 100',
        'cs_parser_hits_ok_total{source="/var/log/swag/nginx/access.log",type="nginx"} 98',
        'cs_parser_hits_ko_total{source="/var/log/swag/nginx/access.log",type="nginx"} 2',
        'cs_bucket_overflowed_total{name="crowdsecurity/http-probing"} 3',
        'cs_appsec_reqs_total{appsec_engine="x",source="y"} 10',
        'cs_appsec_block_total{appsec_engine="x",source="y"} 2',
        'cs_lapi_bouncer_requests_total{bouncer="swag",route="/v1/decisions/stream",method="GET"} 5',
        'cs_lapi_bouncer_requests_total{bouncer="swag",route="/v1/decisions",method="GET"} 1',
    ]))
    assert s["version"] == "v1.6.4"
    assert s["acquisition"] == [{"source": "/var/log/swag/nginx/access.log", "type": "file", "read": 100, "parsed": 98, "unparsed": 2}]
    assert s["overflows"] == {"crowdsecurity/http-probing": 3}
    assert s["appsec"]["blocked"] == 2 and s["bouncers"] == {"swag": 6}


# ------------------------------------------------------------------------------------ against PostgreSQL ---
DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_swag_dashboard_and_detections():
    from lookingglass import db
    from lookingglass.config import Settings
    from lookingglass.dashboards import run_dashboard
    from lookingglass.detections import DetectionEngine

    async def main():
        await db.connect(DSN)
        pool = db.pool()
        try:
            await pool.execute("DELETE FROM events WHERE source IN ('fail2ban') OR program IN ('swag', 'crowdsec-lapi')")
            await pool.execute("DELETE FROM alerts WHERE rule IN ('fail2ban', 'honeypot')")
            now = datetime.now(timezone.utc)
            f2b = [f"{(now - timedelta(minutes=m)).strftime('%Y-%m-%d %H:%M:%S')},000 fail2ban.actions [1]: NOTICE  {x}"
                   for m, x in ((9, "[sshd] Ban 203.0.113.9"), (8, "[nginx-honeypot] Ban 203.0.113.10"),
                                (7, "[sshd] Ban 192.168.1.66"), (6, "[sshd] Unban 203.0.113.9"))]
            hp = Honeypot("/trap")
            events = [parse_line("fail2ban", line, "fail2ban/fail2ban.log", "SWAG", timezone.utc, hp) for line in f2b]
            events.append(parse_line("access", f'198.51.100.7 - - [{now.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /trap HTTP/1.1" 404 1 "-" "x"',
                                     "nginx/access.log", "SWAG", timezone.utc, hp))
            events += lapi.alert_events({**ALERT, "uuid": "test-swag", "start_at": now.isoformat(),
                                         "decisions": [{**ALERT["decisions"][0], "id": 999001}]})
            await db.copy_events([e for e in events if not e.get("uid")])
            await db.insert_events_dedup([e for e in events if e.get("uid")])
            for tab in ("web", "crowdsec", "fail2ban", "honeypot"):
                res = await run_dashboard("swag", 24, tab=tab)
                assert not [(p["id"], p["error"]) for p in res["panels"] if p.get("error")]
                if tab == "fail2ban":
                    kpi = res["panels"][0]["rows"][0]
                    assert kpi["Bans"] == 3 and kpi["Unbans"] == 1 and kpi["Banned now"] >= 2
                if tab == "honeypot":
                    assert res["panels"][0]["rows"][0]["IPs"] == 2
            eng = DetectionEngine(Settings())
            for rule in ("fail2ban", "honeypot"):
                await db.kv_set(f"wm:{rule}", 0)
            await eng.fail2ban_bans()
            await eng.honeypot_hits()
            got = {(r["rule"], str(r["src_ip"])): r["severity"] for r in await pool.fetch(
                "SELECT rule, src_ip, severity FROM alerts WHERE rule IN ('fail2ban', 'honeypot')")}
            assert got[("fail2ban", "192.168.1.66")] == "high"  # banned inside the network
            assert got[("fail2ban", "203.0.113.9")] == "low"
            assert ("fail2ban", "203.0.113.10") not in got  # a honeypot jail: the honeypot rule
            assert got[("honeypot", "203.0.113.10")] == "low" and got[("honeypot", "198.51.100.7")] == "low"
        finally:
            await db.close()
    asyncio.run(main())


def test_lapi_login_trims_and_explains_a_wrong_password():
    import httpx
    from lookingglass.config import Settings

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        if body == {"machine_id": "lookingglass", "password": "s3cret", "scenarios": []}:
            return httpx.Response(200, json={"code": 200, "expire": "2099-01-01T00:00:00Z", "token": "t"})
        return httpx.Response(401, json={"code": 401, "message": "incorrect Username or Password"})

    async def main():
        for password, ok in ((" s3cret\n", True), ("wrong", False)):
            client = lapi.LapiClient(Settings(crowdsec_lapi_url="http://cs:8080", crowdsec_lapi_machine="lookingglass ",
                                              crowdsec_lapi_password=password))
            client.http = httpx.AsyncClient(base_url="http://cs:8080", transport=httpx.MockTransport(handler))
            try:
                if ok:
                    await client.login()
                    assert client.token == "t"
                else:
                    with pytest.raises(lapi.LapiError) as exc:
                        await client.login()
                    msg = str(exc.value)
                    assert "machine 'lookingglass' with a 5-character password" in msg and "--force" in msg
            finally:
                await client.close()
    asyncio.run(main())
