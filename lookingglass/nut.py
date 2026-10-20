"""Network UPS Tools (NUT) client: reads UPS status from an upsd server (port 3493), e.g. the Unraid NUT plugin.

The Unraid API only knows Unraid's built-in UPS service (apcupsd); a UPS managed by the NUT plugin is read here.
Reading variables needs no login on a default upsd. Results use the same shape as the Unraid API's upsDevices.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

_STATUS = {"OL": "Online", "OB": "On Battery", "LB": "Low Battery", "HB": "High Battery", "RB": "Replace Battery",
           "CHRG": "Charging", "DISCHRG": "Discharging", "BYPASS": "Bypass", "CAL": "Calibrating", "OFF": "Offline",
           "OVER": "Overload", "TRIM": "Trimming", "BOOST": "Boosting", "FSD": "Forced Shutdown"}
_LINE = re.compile(r'^(?:UPS|VAR) (\S+)(?: (\S+))? "(.*)"$')


def parse_target(text: str | None, default_host: str | None) -> tuple[str | None, str | None, int]:
    """'ups@192.168.1.10:3493' / '192.168.1.10' / 'ups@' / '' -> (ups name or None for all, host, port)."""
    text = (text or "").strip()
    ups, _, hostport = text.rpartition("@") if "@" in text else ("", "", text)
    host, _, port = hostport.partition(":") if hostport.count(":") == 1 else (hostport, "", "")
    return ups or None, host or default_host, int(port) if port.isdigit() else 3493


def status_text(codes: str) -> str:
    return ", ".join(_STATUS.get(c, c) for c in codes.split()) or "unknown"


async def _ask(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cmd: str, timeout: float) -> list[str]:
    writer.write(cmd.encode() + b"\n")
    await writer.drain()
    lines: list[str] = []
    while True:
        line = (await asyncio.wait_for(reader.readline(), timeout)).decode(errors="replace").strip()
        if not line:
            raise ConnectionError("connection closed by upsd")
        if line.startswith("ERR"):
            raise ConnectionError(f"upsd: {line}")
        if line.startswith("END LIST"):
            return lines
        if not line.startswith("BEGIN LIST"):
            lines.append(line)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def device(name: str, desc: str, var: dict[str, str]) -> dict[str, Any]:
    load = _num(var.get("ups.load"))
    power = _num(var.get("ups.realpower"))
    if power is None and load is not None and _num(var.get("ups.realpower.nominal")):
        power = round(_num(var["ups.realpower.nominal"]) * load / 100, 1)
    model = " ".join(x for x in (var.get("device.mfr") or var.get("ups.mfr"), var.get("device.model") or var.get("ups.model")) if x)
    return {"id": f"nut:{name}", "name": name, "model": model or desc, "source": "NUT",
            "status": status_text(var.get("ups.status", "")), "status_codes": var.get("ups.status", ""),
            "battery": {"chargeLevel": _num(var.get("battery.charge")), "estimatedRuntime": _num(var.get("battery.runtime")),
                        "health": "Replace" if "RB" in var.get("ups.status", "").split() else "Good"},
            "power": {"loadPercentage": load, "currentPower": power, "inputVoltage": _num(var.get("input.voltage")),
                      "outputVoltage": _num(var.get("output.voltage"))}}


async def read_ups(host: str, port: int = 3493, ups: str | None = None, timeout: float = 5.0) -> list[dict[str, Any]]:
    """All UPSes on the upsd server (or just ``ups``) as Unraid-API-shaped dicts. Raises OSError / ConnectionError."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        names = {}
        for line in await _ask(reader, writer, "LIST UPS", timeout):
            m = _LINE.match(line)
            if m:
                names[m[1]] = m[3]
        if ups:
            names = {ups: names.get(ups, "")}
        out = []
        for name, desc in names.items():
            var = {}
            for line in await _ask(reader, writer, f"LIST VAR {name}", timeout):
                m = _LINE.match(line)
                if m and m[2]:
                    var[m[2]] = m[3]
            out.append(device(name, desc, var))
        return out
    finally:
        try:
            writer.write(b"LOGOUT\n")
            writer.close()
        except OSError:
            pass
