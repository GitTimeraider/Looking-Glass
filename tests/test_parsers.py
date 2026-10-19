from datetime import datetime, timezone

from lookingglass.parsers import parse_line
from lookingglass.parsers.filterlog import parse_fields
from lookingglass.parsers.security import ids_from_api, unbound_from_api, parse_zenarmor
from lookingglass.parsers.syslog import parse_syslog

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def test_rfc3164_header():
    m = parse_syslog("<134>Oct 18 11:59:01 fw.lan filterlog[1234]: 5,,,abc,em0,match,block,in,4", now=NOW)
    assert m.host == "fw.lan" and m.program == "filterlog" and m.pid == "1234"
    assert m.ts == datetime(2026, 10, 18, 11, 59, 1, tzinfo=timezone.utc)
    assert m.severity == 6 and m.facility == 16


def test_rfc5424_header():
    m = parse_syslog('<38>1 2026-10-18T11:00:00+02:00 fw.lan sshd 99 - [meta sequenceId="5"] Invalid user bob from 1.2.3.4 port 22', now=NOW)
    assert m.program == "sshd" and m.host == "fw.lan"
    assert m.ts == datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)
    assert m.message.startswith("Invalid user bob")


def test_filterlog_tcp_v4():
    line = ("<134>1 2026-10-18T11:00:00+00:00 fw.lan filterlog 1 - [meta sequenceId=\"1\"] "
            "82,,,fae559338f65e11c53669fc3642c93c2,vtnet1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
            "203.0.113.5,192.168.1.10,51515,22,0,S,1234567,,64240,,mss;sackOK;TS;nop;wscale")
    ev = parse_line(line, now=NOW)
    assert ev["source"] == "firewall" and ev["action"] == "block"
    assert ev["src_ip"] == "203.0.113.5" and ev["dst_ip"] == "192.168.1.10"
    assert ev["src_port"] == 51515 and ev["dst_port"] == 22 and ev["proto"] == "tcp"
    assert ev["interface"] == "vtnet1" and ev["direction"] == "in"
    assert ev["data"]["tcpflags"] == "S"


def test_filterlog_udp_v6():
    rec = parse_fields("100,,,rid,em0,match,pass,out,6,0x00,0x00000,64,udp,17,40,2001:db8::1,2001:db8::2,5353,53,32")
    assert rec["src"] == "2001:db8::1" and rec["dst"] == "2001:db8::2"
    assert rec["srcport"] == "5353" and rec["dstport"] == "53"


def test_nginx_access_attack():
    line = ('<190>Oct 18 11:59:01 fw nginx: 198.51.100.7 - - [18/Oct/2026:11:59:01 +0000] '
            '"GET /../../etc/passwd HTTP/1.1" 404 153 "-" "sqlmap/1.7"')
    ev = parse_line(line, now=NOW)
    assert ev["source"] == "nginx" and ev["src_ip"] == "198.51.100.7"
    assert ev["action"] == "http_404"
    assert "path_traversal" in ev["data"]["tags"] and "scanner_ua" in ev["data"]["tags"]


def test_nginx_error():
    line = ('<187>Oct 18 11:59:01 fw nginx: 2026/10/18 11:59:01 [error] 123#100: *5 limiting requests, excess: 10.5 by zone "x", '
            'client: 198.51.100.8, server: www.example.com, request: "GET / HTTP/1.1"')
    ev = parse_line(line, now=NOW)
    assert ev["action"] == "rate_limited" and ev["src_ip"] == "198.51.100.8" and ev["domain"] == "www.example.com"


def test_unbound_query_and_api():
    ev = parse_line("<30>Oct 18 11:59:01 fw unbound[55]: [55:0] info: 192.168.1.20 evil.example.com. A IN", now=NOW)
    assert ev["source"] == "unbound" and ev["domain"] == "evil.example.com" and ev["src_ip"] == "192.168.1.20"
    ev = unbound_from_api({"time": 1760788741, "client": "192.168.1.20", "domain": "ads.example.", "type": "A",
                           "action": "Block", "rcode": "NXDOMAIN", "blocklist": "ads"})
    assert ev["action"] == "block" and ev["domain"] == "ads.example" and ev["uid"].startswith("dns:")


def test_crowdsec_logfmt():
    line = ('<30>Oct 18 11:59:01 fw crowdsec[1]: time="2026-10-18T11:59:01Z" level=info '
            'msg="Ip 203.0.113.9 performed \'crowdsecurity/ssh-bf\' (6 events over 2.1s) at 2026-10-18 11:59:01 +0000 UTC"')
    ev = parse_line(line, now=NOW)
    assert ev["source"] == "crowdsec" and ev["src_ip"] == "203.0.113.9"
    assert ev["data"]["scenario"] == "crowdsecurity/ssh-bf"


def test_suricata_fast():
    line = ("<33>Oct 18 11:59:01 fw suricata[9]: [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 "
            "[Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 203.0.113.4:51234 -> 192.168.1.5:1433")
    ev = parse_line(line, now=NOW)
    assert ev["source"] == "suricata" and ev["dst_port"] == 1433 and ev["data"]["sid"] == 2010935
    assert ev["src_ip"] == "203.0.113.4"


def test_ids_api():
    ev = ids_from_api({"timestamp": "2026-10-18T11:00:00.000+0000", "flow_id": 1, "src_ip": "1.2.3.4", "src_port": 1,
                       "dest_ip": "10.0.0.1", "dest_port": 80, "proto": "TCP", "alert": "ET WEB test", "alert_sid": 99,
                       "alert_action": "blocked"})
    assert ev["source"] == "suricata" and ev["message"] == "ET WEB test" and ev["action"] == "blocked"


def test_zenarmor_json():
    ev = parse_zenarmor(NOW, "fw", "zenarmor", '{"ip_src_saddr":"192.168.1.30","ip_dst_saddr":"93.184.216.34","ip_dst_port":443,'
                                                '"transport_proto":"TCP","app_name":"TLS","dst_hostname":"Bad.Example","is_blocked":1}')
    assert ev["action"] == "block" and ev["domain"] == "bad.example" and ev["dst_port"] == 443


def test_zenarmor_syslog_format():
    # line shape: daemon=zenarmor, index=<family>, data=<json>  (as streamed by ipdrstreamer)
    line = ('<134>1 2026-10-18T11:00:00+00:00 fw.lan ipdrstreamer 123 - - daemon=zenarmor, index=dns, '
            'data={"start_time":1784368102000,"query":"gsp-ssl.ls.apple.com","qtype":"A","is_blocked":0,'
            '"ip_src_saddr":"192.168.1.20","ip_dst_saddr":"192.168.1.1","src_hwaddr":"aa:bb:cc:00:11:22","src_hostname":"iphone"}')
    ev = parse_line(line, now=NOW)
    assert ev["source"] == "zenarmor" and ev["domain"] == "gsp-ssl.ls.apple.com" and ev["action"] == "dns"
    assert ev["src_ip"] == "192.168.1.20" and ev["data"]["src_hwaddr"] == "aa:bb:cc:00:11:22"
    alert = parse_line('<134>Oct 18 11:59:01 fw zenarmor: daemon=zenarmor, index=alert, '
                       'data={"alertinfo":{"category":["Malware"],"sid":"x"},"is_blocked":1,"ip_src_saddr":"192.168.1.9"}', now=NOW)
    assert alert["action"] == "block" and "Malware" in alert["data"]["security"]


def test_auth_patterns():
    ev = parse_line("<38>Oct 18 11:59:01 fw sshd[1]: Failed password for invalid user admin from 203.0.113.50 port 4444 ssh2", now=NOW)
    assert ev["source"] == "auth" and ev["action"] == "login_failed" and ev["username"] == "admin"
    ev = parse_line("<37>Oct 18 11:59:01 fw audit[1]: /index.php: Web GUI authentication error for 'root' from 192.168.1.66", now=NOW)
    assert ev["action"] == "login_failed" and ev["src_ip"] == "192.168.1.66" and ev["username"] == "root"
    ev = parse_line("<37>Oct 18 11:59:01 fw audit[1]: /index.php: Successful login for user 'root' from: 192.168.1.2 (using local)", now=NOW)
    assert ev["action"] == "login_success"


def test_dhcp_lease():
    ev = parse_line("<30>Oct 18 11:59:01 fw dhcpd[1]: DHCPACK on 192.168.1.44 to aa:bb:cc:dd:ee:ff (phone) via em1", now=NOW)
    assert ev["source"] == "dhcp" and ev["data"]["mac"] == "aa:bb:cc:dd:ee:ff" and ev["data"]["hostname"] == "phone"


def test_generic():
    ev = parse_line("<30>Oct 18 11:59:01 fw configd.py[1]: [abc] request firmware status", now=NOW)
    assert ev["source"] in ("system", "auth") and ev["message"]


def test_nginx_main_ext_and_ban_and_stream():
    line = ('<190>Oct 18 11:59:01 fw nginx: 198.51.100.7 - - [18/Oct/2026:11:59:01 +0000] "GET /wp-login.php HTTP/1.1" 404 10 '
            '"-" "Mozilla/5.0" "-" "www.example.com" sn="www.example.com" rt=0.001 ua="-" us="-" ut="-" ul="-" cs=-')
    ev = parse_line(line, now=NOW)
    assert ev["domain"] == "www.example.com" and "scanner_probe" in ev["data"]["tags"]
    line = ('<190>Oct 18 11:59:01 fw nginx: 198.51.100.7 - - [18/Oct/2026:11:59:01 +0000] "https://www.example.com/.env" 403 10 '
            '"-" "curl/8" "-"')
    ev = parse_line(line, now=NOW)
    assert ev["data"]["path"] == "/.env" and "sensitive_file" in ev["data"]["tags"]
    ev = parse_line("<190>Oct 18 11:59:01 fw nginx: 203.0.113.1 [18/Oct/2026:11:59:01 +0000] TCP 200 1234 567 3.002", now=NOW)
    assert ev["action"] == "stream_200" and ev["src_ip"] == "203.0.113.1"
