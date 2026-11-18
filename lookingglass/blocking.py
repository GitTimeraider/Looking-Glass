"""Blocking addresses in OPNsense: from an alert (Alerts › Block…), by hand (General › Blocked addresses) or
automatically for the worst alerts (Settings › Blocking).

Looking Glass fills one OPNsense alias of type "External (advanced)" through the alias_util API (add / delete /
list) and never touches your rules: you use the alias in a block rule yourself. The ``blocks`` table is the truth -
every minute the alias is compared with it: missing active blocks are added again (OPNsense empties an External
alias on a reboot), expired ones are taken out. Addresses in the alias that Looking Glass did not put there are left
alone.

Safety: the address of the browser that asks, OPNsense itself, loopback / link-local addresses and the "Never block"
list are refused; internal devices only by hand with ``allow_internal`` (the Alerts page warns first); automatic
blocks only ever hit internet addresses.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from . import db
from .config import Settings
from .parsers.common import is_internal_ip, parse_networks

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class BlockError(ValueError):
    """A block that is refused, with a readable reason."""


def normalise(value: Any) -> str:
    """'203.0.113.7' / '203.0.113.0/24' / '2001:db8::1' -> canonical text; BlockError when it is neither."""
    text = str(value or "").strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return str(net.network_address) if net.num_addresses == 1 else str(net)
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise BlockError(f"'{text}' is not an IP address or network") from exc


def _net(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(text, strict=False)


def opnsense_addresses(s: Settings) -> list[str]:
    """OPNsense's own address as far as Looking Glass knows it (the API URL)."""
    host = urlsplit(s.opnsense_url or "").hostname
    try:
        return [str(ipaddress.ip_address(host))] if host else []
    except ValueError:
        return []


def check(s: Settings, address: str, client_ip: str | None = None, allow_internal: bool = False) -> None:
    """Raise BlockError when ``address`` must not be blocked."""
    net = _net(address)
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        raise BlockError(f"{address} is a loopback / link-local / multicast address - blocking it makes no sense")
    if net.num_addresses > (1 << 16 if net.version == 4 else 1 << 80):
        raise BlockError(f"{address} is too large a network (at most a /16 for IPv4, /48 for IPv6)")
    try:
        client = ipaddress.ip_address(client_ip) if client_ip else None
    except ValueError:
        client = None
    if client is not None and client in net:
        raise BlockError(f"{address} contains the address you are using right now ({client_ip}) - you would "
                         "lock yourself out")
    for own in opnsense_addresses(s):
        if ipaddress.ip_address(own) in net:
            raise BlockError(f"{address} contains OPNsense itself ({own})")
    for never in parse_networks(s.block_never):
        if net.version == never.version and (net.subnet_of(never) or never.subnet_of(net)):
            raise BlockError(f"{address} is on your 'Never block' list ({never}) - Settings › Blocking")
    extra = parse_networks(s.internal_networks)
    if is_internal_ip(str(net.network_address), extra) and not allow_internal:
        raise BlockError(f"{address} is an internal address. Blocking it only cuts the device off when the alias is "
                         "also used in a rule on its own interface - confirm to block it anyway.")


# ------------------------------------------------------------------ OPNsense ---
class Alias:
    """The alias_util calls on one OPNsense alias."""

    def __init__(self, s: Settings, client: Any = None) -> None:
        self.s, self.name = s, s.block_alias.strip()
        self._client = client

    async def _api(self):
        if self._client is None:
            from .opnsense import OPNsenseClient
            self._client = OPNsenseClient(self.s)
            self._own = True
        return self._client

    async def close(self) -> None:
        if getattr(self, "_own", False) and self._client is not None:
            await self._client.close()

    async def info(self) -> dict[str, Any]:
        """Whether the alias exists and its type (the API user's privileges are checked on the way)."""
        api = await self._api()
        res = await api.get(f"firewall/alias/getAliasUUID/{quote(self.name)}")
        uuid = (res or {}).get("uuid") if isinstance(res, dict) else None
        if not uuid:
            return {"exists": False}
        item = ((await api.get(f"firewall/alias/getItem/{uuid}")) or {}).get("alias") or {}
        types = item.get("type") or {}
        kind = next((k for k, v in types.items() if isinstance(v, dict) and str(v.get("selected")) == "1"), None) \
            if isinstance(types, dict) else str(types)
        return {"exists": True, "uuid": uuid, "type": kind, "enabled": str(item.get("enabled", "1")) == "1"}

    async def list(self) -> set[str]:
        api = await self._api()
        res = await api.get(f"firewall/alias_util/list/{quote(self.name)}")
        rows = (res or {}).get("rows", []) if isinstance(res, dict) else []
        out = set()
        for r in rows:
            value = r.get("ip") if isinstance(r, dict) else r
            try:
                out.add(normalise(value))
            except BlockError:
                continue
        return out

    async def add(self, address: str) -> None:
        api = await self._api()
        res = await api.post(f"firewall/alias_util/add/{quote(self.name)}", {"address": address})
        if isinstance(res, dict) and str(res.get("status", "done")).lower() not in ("done", "ok"):
            raise BlockError(f"OPNsense did not add {address}: {res}")

    async def delete(self, address: str) -> None:
        api = await self._api()
        res = await api.post(f"firewall/alias_util/delete/{quote(self.name)}", {"address": address})
        if isinstance(res, dict) and str(res.get("status", "done")).lower() not in ("done", "ok"):
            raise BlockError(f"OPNsense did not remove {address}: {res}")


def _err(exc: Exception) -> str:
    from .opnsense import ApiError
    if isinstance(exc, ApiError) and exc.status == 403:
        return "OPNsense refused (HTTP 403): give the API user the privilege 'Firewall: Alias: Edit'"
    if isinstance(exc, ApiError) and exc.status == 404:
        return "OPNsense does not know this alias call (HTTP 404) - is the alias name right?"
    return f"{type(exc).__name__}: {exc}"[:300]


# ------------------------------------------------------------------- blocks ---
OUT_SQL = ("SELECT id, host(ip) || CASE WHEN masklen(ip) IN (32, 128) THEN '' ELSE '/' || masklen(ip) END AS ip, "
           "created_at, expires_at, created_by, reason, alert_id, auto, status, removed_at, removed_by, in_alias, "
           "synced_at, last_error FROM blocks")


async def active_for(ips: list[str]) -> dict[str, dict[str, Any]]:
    """The active block that covers each of these addresses (the Alerts page shows "blocked until …")."""
    if not ips:
        return {}
    rows = await db.pool().fetch(
        "SELECT host(x) AS addr, b.id, b.expires_at, b.auto FROM unnest($1::inet[]) x JOIN blocks b ON x <<= b.ip "
        "WHERE b.status = 'active'", ips)
    return {r["addr"]: db.jsonable({"id": r["id"], "expires_at": r["expires_at"], "auto": r["auto"]}) for r in rows}


async def create(s: Settings, address: str, hours: float | None, reason: str = "", by: str | None = None,
                 alert_id: int | None = None, auto: bool = False, client_ip: str | None = None,
                 allow_internal: bool = False) -> dict[str, Any]:
    """Store a block and put it in the alias right away. An address that is already blocked gets the later end."""
    if not s.block_alias.strip():
        raise BlockError("Blocking is not set up: enter the OPNsense alias under Settings › Blocking")
    if not s.opnsense_enabled:
        raise BlockError("OPNsense is not connected (Settings › OPNsense)")
    address = normalise(address)
    check(s, address, client_ip, allow_internal)
    expires = datetime.now(timezone.utc) + timedelta(hours=hours) if hours and hours > 0 else None
    pool = db.pool()
    row = await pool.fetchrow("SELECT id, expires_at FROM blocks WHERE ip = $1::inet AND status = 'active'", address)
    if row:
        if row["expires_at"] is not None and (expires is None or expires > row["expires_at"]):
            await pool.execute("UPDATE blocks SET expires_at = $2 WHERE id = $1", row["id"], expires)
        bid = row["id"]
    else:
        bid = await pool.fetchval(
            "INSERT INTO blocks (ip, expires_at, created_by, reason, alert_id, auto) VALUES ($1::inet, $2, $3, $4, $5, $6) "
            "RETURNING id", address, expires, by, (reason or "")[:500] or None, alert_id, auto)
    alias = Alias(s)
    try:
        await alias.add(address)
        await pool.execute("UPDATE blocks SET in_alias = true, synced_at = now(), last_error = NULL WHERE id = $1", bid)
    except Exception as exc:  # noqa: BLE001 - kept: the sync loop tries again every minute
        await pool.execute("UPDATE blocks SET in_alias = false, last_error = $2 WHERE id = $1", bid, _err(exc))
        log.warning("block %s: %s", address, _err(exc))
    finally:
        await alias.close()
    log.warning("BLOCKED %s%s by %s%s", address, f" until {expires:%Y-%m-%d %H:%M} UTC" if expires else "",
                by or "?", f" (alert #{alert_id})" if alert_id else "")
    return db.jsonable(dict(await pool.fetchrow(f"{OUT_SQL} WHERE id = $1", bid)))


async def remove(s: Settings, bid: int, by: str | None = None) -> dict[str, Any]:
    pool = db.pool()
    row = await pool.fetchrow(f"{OUT_SQL} WHERE id = $1", bid)
    if not row:
        raise BlockError(f"block #{bid} does not exist")
    if row["status"] == "active":
        await pool.execute("UPDATE blocks SET status = 'removed', removed_at = now(), removed_by = $2 WHERE id = $1",
                           bid, by)
        if s.block_alias.strip() and s.opnsense_enabled:
            alias = Alias(s)
            try:
                await alias.delete(row["ip"])
                await pool.execute("UPDATE blocks SET in_alias = false, synced_at = now(), last_error = NULL WHERE id = $1", bid)
            except Exception as exc:  # noqa: BLE001 - the sync loop takes it out later
                await pool.execute("UPDATE blocks SET last_error = $2 WHERE id = $1", bid, _err(exc))
            finally:
                await alias.close()
        log.warning("UNBLOCKED %s by %s", row["ip"], by or "?")
    return db.jsonable(dict(await pool.fetchrow(f"{OUT_SQL} WHERE id = $1", bid)))


async def listing(limit: int = 300) -> dict[str, Any]:
    rows = await db.pool().fetch(
        f"{OUT_SQL} ORDER BY (status = 'active') DESC, created_at DESC LIMIT $1", limit)
    return {"blocks": db.records(rows), "state": await db.get_snapshot("block_sync")}


# ---------------------------------------------------------------- sync loop ---
async def sync_once(s: Settings, alias: Alias | None = None) -> dict[str, Any]:
    """Expire old blocks, make the alias match the table; returns what was done (also stored as snapshot)."""
    pool = db.pool()
    expired = await pool.fetch(
        "UPDATE blocks SET status = 'expired', removed_at = now(), removed_by = 'expired' "
        "WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= now() RETURNING host(ip) ip")
    state: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(), "alias": s.block_alias.strip()}
    if not state["alias"] or not s.opnsense_enabled:
        state["error"] = "Blocking is off (Settings › Blocking)" if not state["alias"] else "OPNsense is not connected"
        await db.set_snapshot("block_sync", state)
        return state
    own = alias is None
    alias = alias or Alias(s)
    try:
        info = await alias.info()
        state.update(info=info)
        if not info.get("exists"):
            raise BlockError(f"OPNsense has no alias '{state['alias']}': create it under Firewall › Aliases "
                             "(type External (advanced))")
        present = await alias.list()
        active = {r["ip"]: r["id"] for r in await pool.fetch(f"{OUT_SQL} WHERE status = 'active'")}
        # ours that ended: every address a block of Looking Glass ever put there and no active block covers now
        ended = {r["ip"] for r in await pool.fetch(f"{OUT_SQL} WHERE status <> 'active' AND removed_at > now() - interval '30 days'")}
        added, removed, failed = [], [], []
        for ip, bid in active.items():
            if ip in present:
                continue
            try:
                await alias.add(ip)
                added.append(ip)
            except Exception as exc:  # noqa: BLE001
                failed.append(ip)
                await pool.execute("UPDATE blocks SET in_alias = false, last_error = $2 WHERE id = $1", bid, _err(exc))
        for ip in (ended & present) - set(active):
            try:
                await alias.delete(ip)
                removed.append(ip)
            except Exception as exc:  # noqa: BLE001
                failed.append(ip)
                log.warning("unblock %s: %s", ip, _err(exc))
        ok_ids = [bid for ip, bid in active.items() if ip not in failed]
        await pool.execute("UPDATE blocks SET in_alias = true, synced_at = now(), last_error = NULL "
                           "WHERE id = ANY($1::bigint[])", ok_ids)
        await pool.execute("UPDATE blocks SET in_alias = false WHERE status <> 'active' AND in_alias")
        state.update(added=added, removed=removed, failed=failed, active=len(active), in_alias=len(present),
                     foreign=len(present - set(active) - ended))
        if info.get("type") and info["type"] not in ("external", "urltable", "host", "network"):
            state["warning"] = f"The alias type is '{info['type']}': use External (advanced)."
        elif info.get("type") in ("host", "network"):
            state["warning"] = ("The alias is of type Host(s) / Network(s): OPNsense resets it to its configured "
                                "content on every filter reload. Use the type External (advanced).")
        if expired or added or removed:
            log.info("block sync: %d expired, %d added, %d removed", len(expired), len(added), len(removed))
    except Exception as exc:  # noqa: BLE001
        state["error"] = _err(exc) if not isinstance(exc, BlockError) else str(exc)
    finally:
        if own:
            await alias.close()
    await db.set_snapshot("block_sync", state)
    return state


async def auto_block(s: Settings) -> list[str]:
    """Block the internet source of every new open alert of ``block_auto_severity`` or worse (once per alert)."""
    if not (s.block_auto and s.block_alias.strip() and s.opnsense_enabled):
        return []
    level = SEVERITIES.index(s.block_auto_severity if s.block_auto_severity in SEVERITIES else "critical")
    rows = await db.pool().fetch(
        "SELECT id, rule, severity, title, host(src_ip) ip FROM alerts WHERE status = 'open' AND src_ip IS NOT NULL "
        "AND severity = ANY($1::text[]) AND last_seen > now() - interval '30 minutes' "
        "AND NOT coalesce(data ? 'auto_block', false) ORDER BY id", SEVERITIES[level:])
    extra = parse_networks(s.internal_networks)
    done = []
    for r in rows:
        note: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        if is_internal_ip(r["ip"], extra):
            note["skipped"] = "internal address"
        else:
            try:
                b = await create(s, r["ip"], s.block_auto_hours, f"automatic: [{r['severity']}] {r['title']}"[:500],
                                 by="auto", alert_id=r["id"], auto=True)
                note["block"] = b["id"]
                done.append(r["ip"])
            except BlockError as exc:
                note["skipped"] = str(exc)
        await db.pool().execute("UPDATE alerts SET data = coalesce(data, '{}'::jsonb) || jsonb_build_object('auto_block', $2::jsonb) "
                                "WHERE id = $1", r["id"], note)
    return done


async def loop(s: Settings) -> None:
    await asyncio.sleep(45)
    while True:
        try:
            await auto_block(s)
            await sync_once(s)
        except (httpx.HTTPError, OSError) as exc:
            log.warning("block sync: %s", exc)
        except Exception:  # noqa: BLE001
            log.exception("block sync failed")
        await asyncio.sleep(60)
