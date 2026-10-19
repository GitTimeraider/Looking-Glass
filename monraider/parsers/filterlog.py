"""OPNsense / pf ``filterlog`` CSV lines.

Field layout taken from OPNsense core ``src/opnsense/scripts/filter/read_log.py``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .common import event

GENERAL = "rulenr,subrulenr,anchorname,rid,interface,reason,action,dir,ipversion".split(",")
IPV4 = GENERAL + "tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst".split(",")
IPV6 = GENERAL + "class,flow,hoplimit,protoname,protonum,length,src,dst".split(",")
UDP = "srcport,dstport,datalen".split(",")
TCP = "srcport,dstport,datalen,tcpflags,seq,ack,urp,tcpopts".split(",")

# rule id (md5 label / uuid) -> description, refreshed from the OPNsense API
RULE_LABELS: dict[str, str] = {}


def parse_fields(csv: str) -> dict[str, str] | None:
    parts = csv.strip().split(",")
    if len(parts) < 9:
        return None
    rec: dict[str, str] = dict(zip(GENERAL, parts[:9]))
    rest = parts[9:]
    if rec["ipversion"] == "4":
        spec = IPV4
    elif rec["ipversion"] == "6":
        spec = IPV6
    else:
        return rec
    rec.update(zip(spec[9:], rest))
    rest = rest[len(spec) - 9:]
    proto = rec.get("protonum")
    if proto == "6":
        rec.update(zip(TCP, rest))
    elif proto == "17":
        rec.update(zip(UDP, rest))
    return rec


def parse(ts: datetime, host: str | None, message: str) -> dict[str, Any] | None:
    rec = parse_fields(message)
    if not rec or rec.get("action") not in ("pass", "block", "match", "rdr", "nat", "binat", "scrub"):
        return None
    label = RULE_LABELS.get(rec.get("rid", ""), "")
    rec["label"] = label
    direction = {"in": "in", "out": "out"}.get(rec.get("dir", ""), rec.get("dir"))
    return event(
        ts, "firewall", host=host, program="filterlog",
        severity=4 if rec["action"] == "block" else 6,
        action=rec["action"], src_ip=rec.get("src"), dst_ip=rec.get("dst"),
        src_port=rec.get("srcport"), dst_port=rec.get("dstport"),
        proto=(rec.get("protoname") or "").lower() or None,
        interface=rec.get("interface"), direction=direction,
        message=f"{rec['action']} {direction} on {rec.get('interface')} "
                f"{rec.get('src')}:{rec.get('srcport', '')} -> {rec.get('dst')}:{rec.get('dstport', '')} "
                f"{(rec.get('protoname') or '').upper()} {label}".strip(),
        data={k: v for k, v in rec.items() if k in ("rulenr", "rid", "label", "reason", "tcpflags", "length", "ttl", "anchorname")},
    )


def from_api(row: dict[str, Any], ts: datetime) -> dict[str, Any] | None:
    """Convert an entry returned by ``/api/diagnostics/firewall/log`` into an event."""
    action = row.get("action")
    if not action:
        return None
    ev = event(
        ts, "firewall", host=row.get("__host__"), program="filterlog",
        severity=4 if action == "block" else 6, action=action,
        src_ip=row.get("src"), dst_ip=row.get("dst"), src_port=row.get("srcport"), dst_port=row.get("dstport"),
        proto=(row.get("protoname") or "").lower() or None, interface=row.get("interface"),
        direction=row.get("dir"),
        message=f"{action} {row.get('dir')} on {row.get('interface')} {row.get('src')}:{row.get('srcport', '')} -> "
                f"{row.get('dst')}:{row.get('dstport', '')} {(row.get('protoname') or '').upper()} {row.get('label', '')}".strip(),
        data={k: row.get(k) for k in ("rulenr", "rid", "label", "reason", "tcpflags", "length", "ttl") if row.get(k)},
        uid="fw:" + str(row.get("__digest__")),
    )
    return ev
