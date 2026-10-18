#!/usr/bin/env python3
"""Send realistic OPNsense-style syslog traffic to MonRaider (for testing / demos).

    python tools/simulate.py --host 127.0.0.1 --port 5514 --count 2000
"""
from __future__ import annotations

import argparse
import random
import socket
import string
import time
from datetime import datetime, timezone

LAN = [f"192.168.1.{i}" for i in range(10, 40)]
ATTACKERS = ["203.0.113.5", "198.51.100.23", "45.155.205.10", "185.220.101.4", "89.248.165.77"]
WAN_IP = "198.51.100.1"


def rfc5424(program: str, msg: str, pri: int = 134) -> str:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"<{pri}>1 {ts} fw.home.lan {program} {random.randint(100, 99999)} - [meta sequenceId=\"1\"] {msg}"


def filterlog(action: str, src: str, dst: str, sport: int, dport: int, proto: str = "tcp", iface: str = "igb0", direction: str = "in") -> str:
    num = {"tcp": 6, "udp": 17}[proto]
    rest = f"{sport},{dport},0,S,123456,,64240,,mss" if proto == "tcp" else f"{sport},{dport},40"
    return rfc5424("filterlog", f"77,,,02f4bab031b57d1e30553ce08e0ec131,{iface},match,{action},{direction},4,0x0,,64,1234,0,DF,{num},{proto},60,{src},{dst},{rest}")


def scenarios() -> list[str]:
    out: list[str] = []
    # background internet noise
    for _ in range(300):
        out.append(filterlog("block", random.choice(ATTACKERS[2:]) if random.random() < .3 else f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                             WAN_IP, random.randint(1024, 65000), random.choice([22, 23, 80, 443, 445, 3389, 8080, 5900])))
    # port scan from attacker 0
    for port in range(20, 140):
        out.append(filterlog("block", ATTACKERS[0], WAN_IP, 40000, port))
    # allowed inbound to port forward
    for _ in range(40):
        out.append(filterlog("pass", random.choice(ATTACKERS), "192.168.1.5", random.randint(1024, 65000), 443))
    # LAN outbound passes + one suspicious port
    for _ in range(150):
        out.append(filterlog("pass", random.choice(LAN), f"142.250.{random.randint(0, 255)}.{random.randint(1, 254)}", random.randint(1024, 65000), 443, iface="igb1"))
    out.append(filterlog("pass", "192.168.1.33", "185.100.87.41", 51515, 9001, iface="igb1"))
    # ssh brute force
    for user in ["root", "admin", "ubuntu", "test", "oracle", "pi", "git"]:
        out.append(rfc5424("sshd", f"Failed password for invalid user {user} from {ATTACKERS[1]} port {random.randint(30000, 60000)} ssh2", pri=38))
    # web GUI failures then success
    for _ in range(4):
        out.append(rfc5424("audit", f"/index.php: Web GUI authentication error for 'root' from 192.168.1.66", pri=37))
    out.append(rfc5424("audit", "/index.php: Successful login for user 'root' from: 192.168.1.66 (using local)", pri=37))
    # nginx traffic incl. attacks
    paths = ["/", "/index.html", "/api/v1/status", "/static/app.js", "/favicon.ico"]
    for _ in range(150):
        ip = random.choice(ATTACKERS + ["93.184.216.34", "151.101.1.69"])
        path = random.choice(paths)
        out.append(rfc5424("nginx", f'{ip} - - [{datetime.now(timezone.utc):%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" 200 512 "-" "Mozilla/5.0" "-"', pri=190))
    for p in ["/.env", "/wp-login.php", "/../../etc/passwd", "/index.php?id=1%20UNION%20SELECT%20password%20FROM%20users",
              "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", "/.git/config", "/phpmyadmin/"]:
        for _ in range(3):
            out.append(rfc5424("nginx", f'{ATTACKERS[3]} - - [{datetime.now(timezone.utc):%d/%b/%Y:%H:%M:%S +0000}] "GET {p} HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x" "-"', pri=190))
    # unbound: normal queries + DNS tunnel + DGA
    for _ in range(300):
        out.append(rfc5424("unbound", f"[123:0] info: {random.choice(LAN)} {random.choice(['www.google.com', 'github.com', 'api.spotify.com', 'cdn.jsdelivr.net', 'opnsense.org'])}. A IN", pri=30))
    for _ in range(200):
        sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=48))
        out.append(rfc5424("unbound", f"[123:0] info: 192.168.1.21 {sub}.t.exfil-example.net. TXT IN", pri=30))
    for _ in range(12):
        dga = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        out.append(rfc5424("unbound", f"[123:0] info: 192.168.1.27 {dga}.com. A IN", pri=30))
    # crowdsec
    out.append(rfc5424("crowdsec", f'time="{datetime.now(timezone.utc).isoformat()}" level=info msg="Ip {ATTACKERS[1]} performed \'crowdsecurity/ssh-bf\' (6 events over 3s) at 2026-10-18"', pri=30))
    out.append(rfc5424("crowdsec", f'time="{datetime.now(timezone.utc).isoformat()}" level=info msg="(localhost/crowdsec) crowdsecurity/ssh-bf by ip {ATTACKERS[1]} : 4h ban on Ip {ATTACKERS[1]}"', pri=30))
    # suricata
    out.append(rfc5424("suricata", f"[1:2001219:20] ET SCAN Potential SSH Scan [Classification: Attempted Information Leak] [Priority: 2] {{TCP}} {ATTACKERS[0]}:40000 -> {WAN_IP}:22", pri=33))
    out.append(rfc5424("suricata", "[1:2027758:3] ET MALWARE Cobalt Strike Beacon Observed [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.33:50000 -> 185.100.87.41:443", pri=33))
    # dhcp
    out.append(rfc5424("dhcpd", "DHCPACK on 192.168.1.38 to de:ad:be:ef:00:01 (unknown-laptop) via igb1", pri=30))
    # zenarmor (json)
    # Zenarmor syslog line shape: daemon=zenarmor, index=<family>, data=<json>
    out.append(rfc5424("ipdrstreamer", 'daemon=zenarmor, index=conn, data={"start_time":%d,"ip_src_saddr":"192.168.1.33","ip_src_port":50000,'
                                       '"ip_dst_saddr":"185.100.87.41","ip_dst_port":443,"transport_proto":"TCP","app_name":"TLS",'
                                       '"dst_hostname":"update-check.badsite.example","is_blocked":1,"src_hwaddr":"de:ad:be:ef:00:33",'
                                       '"src_hostname":"office-pc","device":{"name":"office-pc","vendor":"Dell","os":"Windows 11"}}' % (time.time() * 1000)))
    out.append(rfc5424("ipdrstreamer", 'daemon=zenarmor, index=alert, data={"ip_src_saddr":"192.168.1.33","ip_dst_saddr":"185.100.87.41",'
                                       '"alert_category":"Command and Control","alertinfo":{"category":["Malware"],"sid":"zen-1"},"is_blocked":1,'
                                       '"dst_hostname":"update-check.badsite.example"}'))
    random.shuffle(out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--rounds", type=int, default=1)
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total = 0
    for _ in range(args.rounds):
        for line in scenarios():
            sock.sendto(line.encode(), (args.host, args.port))
            total += 1
            if total % 200 == 0:
                time.sleep(0.05)
    print(f"sent {total} messages to {args.host}:{args.port}")


if __name__ == "__main__":
    main()
