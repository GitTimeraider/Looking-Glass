from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

IP_RE = re.compile(r"(?<![\d.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])|(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")


# address space that is "ours" (RFC1918, CGNAT, loopback, link-local, ULA, multicast)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128")]


def is_internal_ip(value: Any, extra: list | None = None) -> bool:
    try:
        addr = ipaddress.ip_address(str(value).split("/")[0])
    except ValueError:
        return False
    return any(addr in n for n in INTERNAL_NETS) or any(addr in n for n in (extra or []))


def ip_or_none(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def int_or_none(value: Any) -> int | None:
    try:
        v = int(str(value).strip())
        return v if -2**31 < v < 2**31 else None
    except (TypeError, ValueError):
        return None


def find_ips(text: str) -> list[str]:
    out = []
    for m in IP_RE.finditer(text or ""):
        ip = ip_or_none(m.group(0))
        if ip and ip not in out:
            out.append(ip)
    return out


def event(ts: datetime, source: str, **kw: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {"ts": ts, "source": source}
    for key in ("src_ip", "dst_ip"):
        if key in kw:
            kw[key] = ip_or_none(kw[key])
    for key in ("src_port", "dst_port"):
        if key in kw:
            kw[key] = int_or_none(kw[key])
    ev.update({k: v for k, v in kw.items() if v not in (None, "")})
    return ev
