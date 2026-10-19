from datetime import datetime, timezone

from lookingglass.parsers import nginx
from lookingglass.parsers.security import crowdsec_decision_from_api, parse_generic, unbound_from_api

NOW = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)


def test_unbound_api_numeric_codes_and_hostname_client():
    row = {"uuid": "x1", "time": 1792400000, "client": "laptop.home.lan", "domain": "wpad.home.lan.", "type": "A",
           "action": 0, "rcode": 3, "source": 0, "dnssec_status": 0}
    ev = unbound_from_api(row, {"laptop.home.lan": "192.168.1.33"})
    assert ev["src_ip"] == "192.168.1.33" and ev["action"] == "query" and ev["domain"] == "wpad.home.lan"
    assert ev["data"]["rcode"] == "NXDOMAIN" and ev["data"]["client_name"] == "laptop.home.lan"
    assert ev["data"]["source"] == "Recursion" and ev["uid"] == "dns:x1"
    blocked = unbound_from_api({**row, "client": "192.168.1.20", "action": 1, "rcode": 0, "blocklist": "malware"})
    assert blocked["action"] == "block" and blocked["src_ip"] == "192.168.1.20"
    # older OPNsense versions return names - still accepted
    named = unbound_from_api({**row, "client": "10.0.0.5", "action": "Pass", "rcode": "NXDOMAIN"})
    assert named["action"] == "query" and named["data"]["rcode"] == "NXDOMAIN"
    # unknown hostname: no IP, but the name is kept
    unknown = unbound_from_api(row, {})
    assert unknown.get("src_ip") is None and "laptop.home.lan" in unknown["message"]


def test_crowdsec_decision_opnsense_fields():
    ev = crowdsec_decision_from_api({"id": 9, "source": "crowdsec", "scope_value": "45.9.9.9", "reason": "crowdsecurity/ssh-bf",
                                     "action": "ban", "expiration": "3h"})
    assert ev["src_ip"] == "45.9.9.9" and ev["action"] == "ban" and ev["data"]["origin"] == "crowdsec"


def test_auth_and_vpn_lines():
    cases = {
        ("audit", "user root authenticated successfully for WebGui [using OPNsense\\Auth\\Services\\WebGui + OPNsense\\Auth\\Local] at 192.168.1.20"):
            ("auth", "login_success", "root", "192.168.1.20"),
        ("audit", "user admin could not authenticate for WebGui. [using x + y] at 203.0.113.9"): ("auth", "login_failed", "admin", "203.0.113.9"),
        ("openvpn_server1", "198.51.100.4:51234 TLS: Username/Password authentication succeeded for username 'bob'"):
            ("vpn", "login_success", "bob", "198.51.100.4"),
        ("charon", "07[IKE] <con1|3> IKE_SA con1[3] established between 192.0.2.1[fw]...198.51.100.7[peer]"):
            ("vpn", "vpn_connect", "con1", "198.51.100.7"),
        ("audit", "/index.php: Web GUI authentication error for 'root' from 203.0.113.9"): ("auth", "login_failed", "root", "203.0.113.9"),
    }
    for (prog, msg), (source, action, user, ip) in cases.items():
        ev = parse_generic(NOW, "fw", prog, 5, msg)
        assert (ev["source"], ev["action"], ev["username"], ev["src_ip"]) == (source, action, user, ip), msg


def test_nginx_api_lines():
    ev = nginx.access_from_api({"remote_ip": "203.0.113.5", "username": "-", "time": "19/Oct/2026:10:00:00 +0200", "status": "404",
                                "size": "153", "user_agent": "zgrab/0.x", "request_line": "GET /.env HTTP/1.1",
                                "forwarded_for": "-", "http_referer": "-"}, "www.example.com", NOW)
    assert ev["action"] == "http_404" and ev["domain"] == "www.example.com" and "sensitive_file" in ev["data"]["tags"]
    err = nginx.error_from_api({"date": "2026/10/19", "time": "10:00:01", "severity": "error", "number": "1#0",
                                "message": '*5 limiting requests, excess: 1 by zone "one", client: 198.51.100.7, server: x, request: "GET / HTTP/1.1"'},
                               "global", NOW, tz=timezone.utc)
    assert err["action"] == "rate_limited" and err["src_ip"] == "198.51.100.7" and err["ts"].hour == 10
    st = nginx.stream_from_api({"remote_ip": "198.51.100.8", "time": "19/Oct/2026:10:00:00 +0200", "status": "200",
                                "bytes_sent": "100", "bytes_received": "50", "session_time": "1.5"}, "port 443", NOW)
    assert st["action"] == "stream_200" and st["data"]["bytes_sent"] == 100


def test_dashboard_sql_order():
    from lookingglass.dashboards import sql_order
    cols = ["ip", "country", "n", "last"]
    assert sql_order("SELECT ... GROUP BY 1 ORDER BY 3 DESC LIMIT 25", cols) == {"k": "n", "dir": -1}
    assert sql_order("SELECT ... (SELECT x FROM y ORDER BY 1) ... ORDER BY last DESC LIMIT 5", cols) == {"k": "last", "dir": -1}
    assert sql_order("SELECT ... ORDER BY 9", cols) is None and sql_order("SELECT 1", cols) is None
