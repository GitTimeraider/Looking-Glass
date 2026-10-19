"""nginx (os-nginx plugin) access & error log lines."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from .common import event, find_ips, int_or_none
from .syslog import parse_iso

# combined / main format, optionally prefixed with the server name
_ACCESS = re.compile(
    r'^(?:(?P<vhost>\S+) )?(?P<ip>[0-9a-fA-F:.]+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?:(?P<method>[A-Z]+|-) )?(?P<path>[^"]*?)(?: (?P<proto>HTTP/[\d.]+))?" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?(?P<rest>.*)$'
)
# os-nginx "main_ext" format adds: "$http_x_forwarded_for" "$host" sn="$server_name" rt=... ua="..." us="..." ut="..." ul="..." cs=...
_EXT = re.compile(r'^ "(?P<xff>[^"]*)"(?: "(?P<host>[^"]*)" sn="(?P<sn>[^"]*)")?(?P<kv>.*)$')
# stream (L4) servers: '$remote_addr [$time_local] $protocol $status $bytes_sent $bytes_received $session_time'
_STREAM = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+) \[(?P<time>[^\]]+)\] (?P<proto>TCP|UDP) (?P<status>\d{3}) (?P<sent>\d+) (?P<recv>\d+) (?P<dur>[\d.]+)")
_ERROR = re.compile(r"^(?P<time>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>\w+)\] (?P<msg>.*)$")
_ERR_CLIENT = re.compile(r"client: ([0-9a-fA-F:.]+)")
_ERR_SERVER = re.compile(r"server: ([^,]+)")
_ERR_REQUEST = re.compile(r'request: "([^"]*)"')

# signatures of common attacks / scanners in request lines (used for tagging; detections aggregate)
ATTACK_PATTERNS = [
    ("path_traversal", re.compile(r"\.\./|\.\.%2f|%2e%2e[/%]", re.I)),
    ("sqli", re.compile(r"union(\s|%20|\+)+select|select.+from|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d|benchmark\(|information_schema", re.I)),
    ("xss", re.compile(r"<script|%3cscript|javascript:|onerror=|onload=", re.I)),
    ("rce", re.compile(r"\$\{jndi:|/bin/(ba)?sh|cmd\.exe|;\s*(wget|curl)\s|\|\s*(wget|curl)\s|%60|`|\$\(", re.I)),
    ("sensitive_file", re.compile(r"/\.env|/\.git/|/\.aws/|/\.ssh/|/etc/passwd|/wp-config|/config\.php|\.bak$|\.sql$|/\.htpasswd|/id_rsa", re.I)),
    ("scanner_probe", re.compile(r"/wp-login|/wp-admin|/xmlrpc\.php|/phpmyadmin|/pma/|/cgi-bin/|/boaform|/HNAP1|/vendor/phpunit|/actuator|/solr/|/owa/|/autodiscover|/\.well-known/security|/manager/html|/console/|/geoserver|/remote/login", re.I)),
]
SCANNER_UA = re.compile(r"nmap|nikto|sqlmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|python-requests|go-http-client|curl/|libwww|censys|shodan|internetmeasurement|expanse", re.I)


def classify(path: str, ua: str | None) -> list[str]:
    tags = [name for name, rx in ATTACK_PATTERNS if rx.search(path or "")]
    if ua and SCANNER_UA.search(ua):
        tags.append("scanner_ua")
    return tags


def _nginx_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any] | None:
    msg = message.strip()
    if msg.startswith("{"):
        try:
            return _parse_json(ts, host, program, json.loads(msg))
        except ValueError:
            pass
    m = _ACCESS.match(msg)
    if m:
        status = int(m["status"])
        path = m["path"] or ""
        if path.startswith(("http://", "https://")):  # main_ban format logs "$scheme://$host$request_uri"
            path = "/" + path.split("://", 1)[1].partition("/")[2]
        tags = classify(path, m["ua"])
        ext = _EXT.match(m["rest"] or "")
        vhost = m["vhost"] or (ext and (ext["sn"] or ext["host"])) or None
        return event(
            _nginx_time(m["time"]) or ts, "nginx", host=host, program=program or "nginx",
            severity=4 if (tags or status >= 500) else 6,
            action=f"http_{status}", src_ip=m["ip"], username=None if m["user"] == "-" else m["user"],
            proto="http", domain=vhost,
            message=f'{m["method"] or ""} {path} {status}'.strip(),
            data={"method": m["method"], "path": path[:2000], "status": status,
                  "bytes": int_or_none(m["bytes"]), "referer": m["referer"], "user_agent": m["ua"],
                  "vhost": vhost, "x_forwarded_for": ext["xff"] if ext and ext["xff"] not in ("", "-") else None,
                  "tags": tags},
        )
    m = _STREAM.match(msg)
    if m:
        return event(_nginx_time(m["time"]) or ts, "nginx", host=host, program=program or "nginx", severity=6,
                     action=f"stream_{m['status']}", src_ip=m["ip"], proto=m["proto"].lower(),
                     message=f'{m["proto"]} stream {m["status"]} sent={m["sent"]} recv={m["recv"]} {m["dur"]}s',
                     data={"status": int(m["status"]), "bytes_sent": int(m["sent"]), "bytes_received": int(m["recv"]),
                           "session_time": float(m["dur"]), "tags": []})
    m = _ERROR.match(msg)
    if m or program and "error" in program:
        text = m["msg"] if m else msg
        client = _ERR_CLIENT.search(text)
        server = _ERR_SERVER.search(text)
        req = _ERR_REQUEST.search(text)
        level = (m["level"] if m else "error").lower()
        sev = {"emerg": 0, "alert": 1, "crit": 2, "error": 3, "warn": 4, "notice": 5, "info": 6, "debug": 7}.get(level, 3)
        tags = classify(req.group(1) if req else "", None)
        action = "rate_limited" if "limiting requests" in text else "http_error"
        if "access forbidden by rule" in text or "naxsi" in text.lower():
            action = "waf_block"
        return event(ts, "nginx", host=host, program=program or "nginx", severity=sev, action=action,
                     src_ip=client.group(1) if client else None, domain=server.group(1).strip() if server else None,
                     message=text[:4000], data={"level": level, "request": req.group(1) if req else None, "tags": tags})
    ips = find_ips(msg)
    return event(ts, "nginx", host=host, program=program, severity=6, src_ip=ips[0] if ips else None, message=msg[:4000])


def _parse_json(ts: datetime, host: str | None, program: str | None, d: dict[str, Any]) -> dict[str, Any]:
    status = int_or_none(d.get("status"))
    req = d.get("request") or ""
    path = d.get("request_uri") or d.get("uri") or (req.split(" ")[1] if req.count(" ") >= 1 else req)
    ua = d.get("http_user_agent") or d.get("user_agent")
    tags = classify(path, ua)
    t = parse_iso(str(d.get("time_iso8601") or d.get("time") or "")) or ts
    return event(t, "nginx", host=host, program=program or "nginx", severity=4 if tags or (status or 0) >= 500 else 6,
                 action=f"http_{status}" if status else None,
                 src_ip=d.get("remote_addr") or d.get("client_ip"), domain=d.get("server_name") or d.get("host"),
                 proto="http", message=f'{d.get("request_method", "")} {path} {status}',
                 data={**{k: d[k] for k in list(d)[:40]}, "path": path, "status": status, "user_agent": ua, "tags": tags})
