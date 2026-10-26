"""Threat intelligence and traps.

* Feeds (downloaded daily, stored in intel_indicators): abuse.ch URLhaus (malware domains), ThreatFox (malware / C2
  domains and IPs), Feodo Tracker (botnet C2 IPs), SSLBL (malware JA3 TLS fingerprints), the Tor relay and exit lists,
  and a built-in list of crypto-mining pools. Matched against DNS lookups, connections and TLS fingerprints.
* Newly seen domains (seen_domains): the first lookup of a domain on the network; optionally the registration date
  via RDAP, with an alert for very young domains.
* Canary addresses: IPs / ports nothing should ever contact.
* ARP spoofing: the firewall's ARP table and kernel messages.
* Exposure: new / changed port forwards and firewall rules (OPNsense API), see opnsense.Poller.poll_exposure.

All of it can be switched off, tuned and given exceptions under Settings › Threat intel & traps.
"""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import logging
import socket
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import db
from .behavior import Matcher
from .config import Settings
from .detections import (ALLOWED_AGG, FW_BLOCKED_AGG, FW_RULE_AGG, Rating, corroborate, dga_like, evidence, ignore_list,
                         ignored_domain, raise_alert, registered_domain, verdict)
from .parsers.common import is_internal_ip

log = logging.getLogger(__name__)

# well-known mining pools (domains incl. subdomains); extend under Settings › Threat intel & traps
MINING_POOLS = (
    "2miners.com", "antpool.com", "auxpool.com", "binance.com/pool", "braiins.com", "btc.com", "c3pool.com",
    "crazypool.org", "dwarfpool.com", "emcd.io", "ethermine.org", "f2pool.com", "flexpool.io", "hashcity.org",
    "hashvault.pro", "herominers.com", "hiveon.net", "kryptex.network", "minergate.com", "minexmr.com",
    "miningpoolhub.com", "moneroocean.stream", "monerohash.com", "nanopool.org", "nicehash.com", "poolin.com",
    "prohashing.com", "slushpool.com", "supportxmr.com", "unmineable.com", "viabtc.com", "woolypooly.com",
    "xmrpool.eu", "zergpool.com", "zpool.ca", "xmrig.com", "gulf.moneroocean.stream", "pool.hashvault.pro",
    "mine.c3pool.com", "pool.supportxmr.com", "xmr.2miners.com", "rx.unmineable.com",
)
# Sites where anyone can host files / pages under a path (github.com/<user>/..., steamcommunity.com/profiles/<id>,
# cdn.discordapp.com/attachments/...). URLhaus and ThreatFox list malware URLs on them (payloads in GitHub releases,
# Steam profiles as C2 "dead drops"), but only the URL is bad: DNS shows just the host name, so listing the host would
# flag every visit to the site. Domains incl. subdomains - only ones whose subdomains all belong to the platform
# (not e.g. github.io or amazonaws.com, where <name>.github.io is someone's own site).
SHARED_HOSTS = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "steamcommunity.com", "steampowered.com", "steamstatic.com",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
    "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz", "box.com",
    "microsoft.com", "live.com", "onedrive.com", "1drv.ms", "office.com", "windows.net",
    "apple.com", "icloud.com", "amazon.com", "cloudflare.com", "archive.org",
    "telegram.org", "t.me", "telegram.me", "telegra.ph", "pastebin.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com", "reddit.com", "vk.com",
    "bit.ly", "tinyurl.com",
)
# raise when what parse_feed keeps changes: the feeds are then downloaded again right away instead of after a day
FEED_FORMAT = 2
# ThreatFox: IOCs below this confidence (0-100) are skipped
THREATFOX_MIN_CONFIDENCE = 50
# "sources": where a feed can be downloaded, tried in order until one answers with entries - a list that moved or
# disappeared (404, 410, ...) falls through to the next one. "json": POSTed instead of a GET; "key": needs the abuse.ch
# Auth-Key (sent in the Auth-Key header, also to the other abuse.ch downloads when set). The old URLhaus / ThreatFox
# downloads (urlhaus.abuse.ch/downloads/hostfile/, threatfox.abuse.ch/export/csv/recent/) are gone: their APIs only.
FEEDS: dict[str, dict[str, Any]] = {
    "urlhaus": {"setting": "intel_urlhaus", "hours": 24, "label": "URLhaus", "abusech": True, "sources": [
        {"url": "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/", "key": True}]},
    "threatfox": {"setting": "intel_threatfox", "hours": 24, "label": "ThreatFox", "abusech": True, "sources": [
        {"url": "https://threatfox-api.abuse.ch/api/v1/", "json": {"query": "get_iocs", "days": 7}, "key": True}]},
    "feodo": {"setting": "intel_feodo", "hours": 24, "label": "Feodo Tracker", "abusech": True, "sources": [
        {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"},
        {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"}]},
    "sslbl_ja3": {"setting": "intel_ja3", "hours": 24, "label": "SSLBL JA3", "abusech": True, "sources": [
        {"url": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"}]},
    "tor_relay": {"setting": "intel_tor", "hours": 12, "label": "Tor relays", "sources": [
        {"url": "https://onionoo.torproject.org/summary?running=true"}]},
    "tor_exit": {"setting": "intel_tor", "hours": 12, "label": "Tor exit nodes", "sources": [
        {"url": "https://check.torproject.org/torbulkexitlist"},
        {"url": "https://check.torproject.org/exit-addresses"},
        {"url": "https://onionoo.torproject.org/summary?running=true&flag=Exit"}]},
}


def parse_sources(text: str) -> dict[str, list[dict[str, Any]]]:
    """Your own feed addresses (Settings › Threat intel & traps › Feed download addresses), by feed: one per line,
    'feed: URL' or 'feed: POST URL {json}'. Empty lines and # comments are skipped; a wrong line raises ValueError."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, rest = line.partition(":")
        name, rest = name.strip().lower(), rest.strip()
        if not sep or name not in FEEDS:
            raise ValueError(f"line {n}: start with the feed name and a colon ({', '.join(FEEDS)}), e.g. feodo: https://...")
        src: dict[str, Any] = {}
        if rest[:5].upper() == "POST ":
            url, _, body = rest[5:].strip().partition(" ")
            try:
                src["json"] = json.loads(body) if body.strip() else {}
            except ValueError as exc:
                raise ValueError(f"line {n}: the POST body is not valid JSON ({exc})") from exc
        else:
            url = rest
        if not url.startswith(("http://", "https://")) or " " in url:
            raise ValueError(f"line {n}: '{url}' is not an http:// or https:// address")
        out[name].append({**src, "url": url, "custom": True})
    return dict(out)


def _abusech(url: str) -> bool:
    host = (httpx.URL(url).host or "").lower()
    return host == "abuse.ch" or host.endswith(".abuse.ch")


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def shared_host(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == h or d.endswith("." + h) for h in SHARED_HOSTS)


def _threatfox_row(value: str, kind: str, threat: str, malware: str) -> tuple[str, str, str | None] | None:
    info = " / ".join(x for x in (malware, threat.replace("_", " ")) if x and x.lower() != "none") or None
    if kind == "domain":
        return ("domain", value.lower().rstrip("."), info)
    if kind == "ip:port" and (ip := _ip(value.rsplit(":", 1)[0])):
        return ("ip", ip, info)
    if kind == "url":
        host = value.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
        return ("ip", host, info) if _ip(host) else ("domain", host, info)
    return None


def _api_data(name: str, text: str) -> list[dict[str, Any]]:
    """The entries of an abuse.ch API answer (URLhaus: "urls", ThreatFox: "data"); a refused query raises."""
    r = json.loads(text)
    st = r.get("query_status")
    if st == "no_results":
        return []
    if st != "ok":
        raise RuntimeError(f"abuse.ch API: {st or 'unexpected answer'}" +
                           (" - check the Auth-Key (Settings › Threat intel & traps)" if "auth" in str(st).lower() else ""))
    return (r.get("urls") if name == "urlhaus" else r.get("data")) or []


def parse_feed(name: str, text: str) -> list[tuple[str, str, str | None]]:
    """(kind, value, info) rows of one downloaded feed (URLhaus / ThreatFox: the API's JSON or the old download)."""
    out: list[tuple[str, str, str | None]] = []
    if name in ("urlhaus", "threatfox") and text.lstrip().startswith("{"):
        for e in _api_data(name, text):
            if name == "urlhaus":
                host = str(e.get("host") or "").strip().strip("[]").lower().rstrip(".")
                if host and host != "localhost":
                    info = "malware download site" + (f" ({e['threat'].replace('_', ' ')})" if e.get("threat") else "")
                    out.append(("ip", _ip(host), info) if _ip(host) else ("domain", host, info))
            elif _confidence(e.get("confidence_level")) < THREATFOX_MIN_CONFIDENCE:
                continue
            elif row := _threatfox_row(str(e.get("ioc") or "").strip(), str(e.get("ioc_type") or ""),
                                       str(e.get("threat_type") or ""), str(e.get("malware_printable") or "")):
                out.append(row)
        return _unique(out)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if name == "urlhaus":
        for ln in lines:
            parts = ln.split()
            if len(parts) >= 2 and parts[1] not in ("localhost",):
                out.append(("domain", parts[1].lower().rstrip("."), "malware download site"))
    elif name == "threatfox":
        for row in csv.reader(lines, skipinitialspace=True):
            if len(row) < 8:
                continue
            if r := _threatfox_row(row[2].strip(), row[3].strip(), row[4].strip(), row[7].strip()):
                out.append(r)
    elif name == "feodo":
        out += [("ip", ip, "botnet command & control server") for ln in lines if (ip := _ip(ln.split(",")[0]))]
    elif name == "sslbl_ja3":
        for row in csv.reader(lines):
            if row and len(row[0].strip()) == 32:
                out.append(("ja3", row[0].strip().lower(), (row[3].strip() if len(row) > 3 else None) or "malware"))
    elif name == "tor_relay" or (name == "tor_exit" and text.lstrip().startswith("{")):  # Onionoo JSON
        for relay in (json.loads(text).get("relays") or []):
            for a in relay.get("a") or []:
                if ip := _ip(a):
                    out.append(("ip", ip, "Tor relay" if name == "tor_relay" else "Tor exit node"))
    elif name == "tor_exit":  # the bulk list (one IP per line) or exit-addresses ("ExitAddress <ip> <date>")
        for ln in lines:
            parts = ln.split()
            ip = _ip(parts[1]) if parts[0] == "ExitAddress" and len(parts) > 1 else _ip(ln)
            if ip:
                out.append(("ip", ip, "Tor exit node"))
    return _unique(out)


def _confidence(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 100  # not given: keep


def _unique(rows: list[tuple[str, str, str | None]]) -> list[tuple[str, str, str | None]]:
    """One row per (kind, value), without the hosts of shared sites (SHARED_HOSTS)."""
    return list({(k, v): (k, v, i) for k, v, i in rows if not (k == "domain" and shared_host(v))}.values())


class Intel:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self._sets: dict[str, dict[str, dict[str, str | None]]] = {}
        self._version: Any = None
        self._rdap_times: list[float] = []

    def enabled(self, feed: str) -> bool:
        v = getattr(self.s, FEEDS[feed]["setting"])
        return v not in (False, "off")

    # ------------------------------------------------------------ download ---
    async def _download(self, client: httpx.AsyncClient, name: str, feed: dict[str, Any]) -> tuple[list, str]:
        """(rows, url) from the first of the feed's sources - your own addresses first, then the built-in ones - that
        answers with entries; raises with what each one said."""
        key = self.s.abusech_auth_key if feed.get("abusech") else ""
        errors: list[str] = []
        try:
            own = parse_sources(self.s.intel_sources).get(name, [])
        except ValueError as exc:
            own = []
            errors.append(f"your feed addresses: {exc}")
        for src in own + feed["sources"]:
            url = src["url"]
            h = {"Auth-Key": key} if key and _abusech(url) else {}  # the key never goes to other hosts
            if src.get("key") and not key:
                errors.append("needs an abuse.ch Auth-Key (Settings › Threat intel & traps: get a free one at auth.abuse.ch "
                              "› Optional › Generate Auth-Key)")
                continue
            try:
                r = await (client.post(url, headers=h, json=src["json"]) if "json" in src else client.get(url, headers=h))
                if r.status_code in (401, 403) and feed.get("abusech") and _abusech(url):
                    raise RuntimeError(f"HTTP {r.status_code}: abuse.ch " + ("refused the Auth-Key - check it under Settings › "
                                       "Threat intel & traps" if key else "wants an Auth-Key (Settings › Threat intel & traps)"))
                r.raise_for_status()
                rows = parse_feed(name, r.text)
                if not rows:
                    raise RuntimeError("the download contained no entries")
                return rows, url
            except Exception as exc:  # noqa: BLE001 - the next source may still work
                msg = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else str(exc) or type(exc).__name__
                errors.append(("your address " if src.get("custom") else "") + f"{httpx.URL(url).host}{httpx.URL(url).path}: {msg}")
        raise RuntimeError("; ".join(errors))

    async def update(self, force: bool = False) -> dict[str, Any]:
        status: dict[str, Any] = await db.kv_get("intel:status", {}) or {}
        headers = {"User-Agent": "Looking-Glass (self-hosted security monitor)"}
        changed = False
        async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers=headers) as client:
            for name, feed in FEEDS.items():
                st = status.get(name) or {}
                if not self.enabled(name):
                    if st.get("count"):
                        await db.pool().execute("DELETE FROM intel_indicators WHERE feed = $1", name)
                        changed = True
                    status[name] = {"enabled": False}
                    continue
                try:
                    own = json.dumps(parse_sources(self.s.intel_sources).get(name, []), sort_keys=True)
                except ValueError:
                    own = None
                # changed parsing or your own addresses for this feed: download again now
                if not force and st.get("ok") and st.get("format") == FEED_FORMAT and st.get("own") == own and \
                        time.time() - st.get("updated", 0) < feed["hours"] * 3600:
                    continue
                try:
                    rows, url = await self._download(client, name, feed)
                    async with db.pool().acquire() as con, con.transaction():
                        await con.execute("DELETE FROM intel_indicators WHERE feed = $1", name)
                        await con.copy_records_to_table("intel_indicators", columns=["kind", "value", "feed", "info"],
                                                        records=[(k, v, name, i) for k, v, i in rows])
                    status[name] = {"enabled": True, "ok": True, "count": len(rows), "updated": time.time(), "error": None,
                                    "source": url, "format": FEED_FORMAT, "own": own}
                    changed = True
                    log.info("threat feed %s: %d entries from %s", name, len(rows), url)
                except Exception as exc:  # noqa: BLE001
                    status[name] = {**st, "enabled": True, "ok": False, "error": str(exc)[:600], "tried": time.time()}
                    log.warning("threat feed %s: %s", name, exc)
        await db.kv_set("intel:status", status)
        await self.close_shared_host_alerts()
        if changed:
            await db.kv_set("intel:version", time.time())
        return status

    async def close_shared_host_alerts(self) -> None:
        """Open feed alerts for a shared site (raised before those were left out of the feeds): closed."""
        rows = await db.pool().fetch("SELECT id, data->>'indicator' AS ind FROM alerts WHERE rule = 'threat_feed' "
                                     "AND status <> 'closed' AND data ? 'indicator'")
        if ids := [r["id"] for r in rows if r["ind"] and shared_host(r["ind"])]:
            await db.pool().execute(
                "UPDATE alerts SET status = 'closed', close_reason = 'resolved', description = coalesce(description, '') || $2 "
                "WHERE id = ANY($1::bigint[])", ids, "\n\nClosed automatically: the feed listed a single malicious URL "
                "on this site, not the site itself - no longer flagged.")
            log.info("closed %d threat feed alert(s) for shared sites (github.com, steamcommunity.com, ...)", len(ids))

    async def updater(self) -> None:
        await asyncio.sleep(60)
        while True:
            try:
                await self.update()
            except Exception:  # noqa: BLE001
                log.exception("threat feed update failed")
            await asyncio.sleep(3600)

    async def sets(self) -> dict[str, dict[str, dict[str, str | None]]]:
        """kind -> value -> {feed: info}"""
        version = await db.kv_get("intel:version")
        if version != self._version or not self._sets:
            sets: dict[str, dict[str, dict[str, str | None]]] = defaultdict(lambda: defaultdict(dict))
            for r in await db.pool().fetch("SELECT kind, value, feed, info FROM intel_indicators"):
                sets[r["kind"]][r["value"]][r["feed"]] = r["info"]
            self._sets, self._version = {k: dict(v) for k, v in sets.items()}, version
        return self._sets

    def mining_list(self) -> list[str]:
        extra = ignore_list(self.s.mining_domains)
        return [d for d in MINING_POOLS if "/" not in d] + extra

    # -------------------------------------------------------------- matching ---
    async def match(self, internal, watermark, commit) -> None:
        """New DNS lookups, connections and TLS fingerprints against the feeds."""
        last, current = await watermark("intel")
        if current <= last:
            return
        sets = await self.sets()
        allow_dom = ignore_list(self.s.intel_allow) + ignore_list(self.s.dns_ignore_domains)
        allow_ip = Matcher(self.s.intel_allow)
        tor_ok = Matcher(self.s.intel_tor_allow)
        domains, ips, ja3 = sets.get("domain", {}), sets.get("ip", {}), sets.get("ja3", {})
        mining = self.mining_list() if self.s.intel_mining else []
        pool = db.pool()

        def first(feeds: dict[str, str | None]) -> tuple[str, str | None]:
            return next(iter(feeds.items()))

        def feed_hit(domain: str) -> tuple[str, str, str | None] | None:
            parts = domain.lower().rstrip(".").split(".")
            for i in range(len(parts) - 1):
                cand = ".".join(parts[i:])
                if cand in domains:
                    return (cand, *first(domains[cand]))
            return None

        dns = await pool.fetch(
            "SELECT host(src_ip) ip, domain, count(*) n, bool_or(action IN ('block', 'drop', 'nxdomain')) blocked FROM events "
            "WHERE id > $1 AND id <= $2 AND domain IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2", last, current)
        new_domains: dict[str, str] = {}
        for r in dns:
            ip, domain = r["ip"], r["domain"].lower().rstrip(".")
            if not internal(ip):
                continue
            if self.s.nod_enabled:
                new_domains.setdefault(registered_domain(domain), ip)
            if allow_dom and ignored_domain(domain, allow_dom):
                continue
            if mining and ignored_domain(domain, mining):
                await raise_alert(
                    "crypto_mining", corroborate(Rating("high", "a mining pool was contacted - a crypto miner (often "
                                                                "malware, or an unwanted browser / app miner)", sticky=True),
                                                 await evidence(ip, "crypto_mining"), 1),
                    f"Crypto mining: {ip} → {domain}", f"mining:{ip}", src_ip=ip, events={"ip": ip, "q": domain},
                    count=r["n"], blocked=r["blocked"] and "the lookup was blocked", description=f"{ip} looked up / connected to the mining pool {domain}. If this is your "
                                              "own miner: add the domain under Settings › Threat intel & traps › Never "
                                              "flag.")
                continue
            if hit := feed_hit(domain):
                listed, feed, info = hit
                rating = Rating("medium" if r["blocked"] else "high",
                                f"{FEEDS[feed]['label']} lists {listed} ({info or 'malicious'})"
                                + (" - the lookup was blocked" if r["blocked"] else ""), sticky=True)
                await raise_alert(
                    "threat_feed", corroborate(rating, await evidence(ip, "threat_feed"), 1),
                    f"{ip} looked up a known malicious domain: {domain}", f"feed:{ip}:{listed}", src_ip=ip,
                    events={"ip": ip, "q": domain}, count=r["n"], data={"feed": feed, "indicator": listed, "info": info},
                    blocked=r["blocked"] and "the lookup was blocked",
                    description=f"{domain} is listed by {FEEDS[feed]['label']} ({info or 'malicious'}). The device may be "
                                "infected, or a malicious link / ad was opened. False positive? Settings › Threat intel & "
                                "traps › Never flag these domains / IPs.")
        if new_domains:
            await self._new_domains(new_domains)

        if ips:
            conns = await pool.fetch(
                f"SELECT host(src_ip) src, host(dst_ip) dst, max(dst_port) port, count(*) n, {ALLOWED_AGG} passed, "
                f"{FW_BLOCKED_AGG} fw_blocked, {FW_RULE_AGG} fw_rule, array_agg(DISTINCT dst_port) ports, "
                "bool_or(source = 'firewall' AND action = 'pass' AND direction = 'out') left_wan "
                "FROM events WHERE id > $1 AND id <= $2 "
                "AND source IN ('firewall', 'zenarmor', 'suricata') AND src_ip IS NOT NULL AND dst_ip IS NOT NULL "
                "GROUP BY 1, 2", last, current)
            redirect = await self._redirected(conns)
            for r in conns:
                src, dst = r["src"], r["dst"]
                how = verdict(r["passed"], r["fw_blocked"], r["fw_rule"])
                if internal(src) and not internal(dst) and dst in ips and not allow_ip.match(dst, src):
                    if redirect(r):
                        continue  # only ports a NAT port forward sends to your own DNS / NTP server: never left
                    bad = {f: i for f, i in ips[dst].items() if not f.startswith("tor")}
                    feed, info = first(bad or ips[dst])
                    if not bad:
                        if self.s.intel_tor == "off" or tor_ok.match(src):
                            continue
                        rating = Rating("medium" if r["passed"] else "low", "a device connects to the Tor network - "
                                        "hides where traffic goes (privacy tools, but also malware and data theft)"
                                        + ("; the connection was ALLOWED" if r["passed"] else f"; the connection was {how}"),
                                        sticky=True)
                        hint = ""
                        if {p for p in r["ports"] if p is not None} <= {53, 123}:
                            hint = (" Only DNS / NTP ports: if a NAT port forward sends those to your own resolver / "
                                    "time server, give Looking Glass's API user the 'Firewall: NAT: Port Forward' "
                                    "privilege (or tick 'Log' on the NAT rule) so it knows - then this is not raised.")
                        await raise_alert("tor", corroborate(rating, await evidence(src, "tor"), 1),
                                          f"{src} {'connects' if r['passed'] else 'tries to connect'} to the Tor network ({dst})"
                                          + ("" if r["passed"] else " - blocked"), f"tor:{src}", src_ip=src, dst_ip=dst,
                                          events={"ip": src}, count=r["n"], blocked=not r["passed"] and f"the connection was {how}",
                                          description=f"{src} contacted Tor relay {dst}: {how}. "
                                                      "Allowed on purpose? Settings › Threat intel & traps › Devices allowed "
                                                      "to use Tor." + hint)
                        continue
                    rating = Rating("critical" if r["passed"] else "medium",
                                    f"{FEEDS[feed]['label']}: {info or 'malicious'}"
                                    + (" - and the connection was ALLOWED" if r["passed"] else f" - {how}"), sticky=True)
                    await raise_alert(
                        "threat_feed", corroborate(rating, await evidence(src, "threat_feed"), 1),
                        f"{src} → known malicious address {dst}:{r['port'] or '?'}" + ("" if r["passed"] else " (blocked)"),
                        f"feed:{src}:{dst}", src_ip=src,
                        dst_ip=dst, events={"ip": src}, count=r["n"], data={"feed": feed, "indicator": dst, "info": info},
                        blocked=not r["passed"] and f"the connection was {how}",
                        description=f"{dst} is listed by {FEEDS[feed]['label']} ({info or 'malicious'}); the connection was "
                                    f"{how}. A device talking to a command & control server is very likely infected: "
                                    "isolate it and check it.")
                elif (self.s.intel_tor == "both" and r["passed"] and not internal(src) and internal(dst)
                      and "tor_exit" in ips.get(src, {}) and not allow_ip.match(src)):
                    await raise_alert("tor", Rating("low", "a Tor exit node reached one of your services (anonymous "
                                                           "visitor - often scanners and attackers)"),
                                      f"Tor exit node {src} reached {dst}:{r['port'] or '?'}", f"tor_in:{src}",
                                      src_ip=src, dst_ip=dst, events={"ip": src}, count=r["n"])

        if ja3:
            rows = await pool.fetch(
                "SELECT host(src_ip) ip, lower(coalesce(data->>'ja3', data->>'ja3_hash')) fp, max(domain) sni, count(*) n "
                "FROM events WHERE id > $1 AND id <= $2 AND src_ip IS NOT NULL AND coalesce(data->>'ja3', data->>'ja3_hash') "
                "IS NOT NULL GROUP BY 1, 2", last, current)
            for r in rows:
                if r["fp"] in ja3 and internal(r["ip"]) and not allow_ip.match(r["ip"]):
                    _, info = first(ja3[r["fp"]])
                    await raise_alert(
                        "malicious_tls", corroborate(Rating("high", f"TLS fingerprint of {info or 'malware'} (SSLBL)",
                                                            sticky=True), await evidence(r["ip"], "malicious_tls"), 1),
                        f"{r['ip']}: TLS fingerprint of {info or 'malware'}", f"ja3:{r['ip']}:{r['fp']}", src_ip=r["ip"],
                        events={"ip": r["ip"]}, count=r["n"],
                        description=f"A program on {r['ip']} made a TLS connection{' to ' + r['sni'] if r['sni'] else ''} with "
                                    f"JA3 {r['fp']}, which SSLBL lists for {info or 'malware'}. JA3 lists contain false "
                                    "positives - check which program it is before acting.")
        await commit("intel", current)

    # ---------------------------------------------------- newly seen domains ---
    async def _redirected(self, conns: list[Any]):
        """A test for a group of connection events (src, dst, ports, left_wan): every port is one a NAT port forward
        sends to a local server (DNS / NTP redirect), and the firewall never logged it leaving towards the internet.
        Zenarmor sees packets before NAT and the firewall's pass log keeps the original destination, so a redirected
        NTP query to a pool server that is also a Tor relay still shows that relay. Known redirects: the configured
        port forwards (OPNsense API) or the redirect's own log lines ('rdr', NAT rule with logging on)."""
        redirects = nat_redirects(await db.get_snapshot("nat_rules"))
        seen: set[tuple[str, int]] = set()
        if conns:
            seen = {(str(x["src_ip"]), x["dst_port"]) for x in await db.pool().fetch(
                "SELECT DISTINCT src_ip, dst_port FROM events WHERE source = 'firewall' AND action = 'rdr' "
                "AND src_ip IS NOT NULL AND dst_port IS NOT NULL AND ts > now() - interval '1 hour'")}

        def test(r: Any) -> bool:
            ports = list(r["ports"] or [])
            return bool(ports) and not r["left_wan"] and all(
                p is not None and ((r["src"], p) in seen or any(lo <= p <= hi for lo, hi, _ in redirects)) for p in ports)
        return test

    async def _new_domains(self, domains: dict[str, str]) -> None:
        pool = db.pool()
        rows = await pool.fetch(
            "INSERT INTO seen_domains (domain, first_client) SELECT d, c::inet FROM unnest($1::text[], $2::text[]) AS t(d, c) "
            "ON CONFLICT (domain) DO NOTHING RETURNING domain", list(domains), list(domains.values()))
        if rows and await db.kv_get("nod:since") is None:
            await db.kv_set("nod:since", time.time())

    async def rdap(self, internal) -> None:
        """Registration dates of newly seen domains; alert on lookups of very young domains."""
        if not (self.s.nod_enabled and self.s.nod_rdap):
            return
        since = await db.kv_get("nod:since")
        if not since or time.time() - since < 2 * 86400:
            return  # the first two days everything is "new"
        now = time.time()
        self._rdap_times = [t for t in self._rdap_times if now - t < 3600]
        budget = self.s.nod_lookups_per_hour - len(self._rdap_times)
        if budget <= 0:
            return
        pool = db.pool()
        todo = await pool.fetch("SELECT domain, host(first_client) client FROM seen_domains WHERE NOT rdap_checked "
                                "AND first_seen > now() - interval '2 days' ORDER BY first_seen LIMIT $1", min(budget, 20))
        allow = ignore_list(self.s.intel_allow) + ignore_list(self.s.dns_ignore_domains)
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            for r in todo:
                self._rdap_times.append(time.time())
                registered = None
                try:
                    resp = await client.get(f"https://rdap.org/domain/{r['domain']}")
                    if resp.status_code == 200:
                        for e in resp.json().get("events") or []:
                            if e.get("eventAction") == "registration" and e.get("eventDate"):
                                registered = datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                except (httpx.HTTPError, ValueError):
                    pass
                await pool.execute("UPDATE seen_domains SET rdap_checked = true, registered = $2 WHERE domain = $1",
                                   r["domain"], registered)
                if not registered or ignored_domain(r["domain"], allow):
                    continue
                age = datetime.now(timezone.utc) - registered
                if age > timedelta(days=self.s.nod_young_days):
                    continue
                ip = r["client"]
                rating = Rating("low", f"the domain was registered only {age.days} day(s) ago - new domains are a favourite "
                                       "of phishing and malware", sticky=True)
                if dga_like(r["domain"]):
                    rating.up("and its name looks random (DGA)")
                corroborate(rating, await evidence(ip, "young_domain"), 1)
                await raise_alert("young_domain", rating, f"{ip} looked up a {age.days}-day-old domain: {r['domain']}",
                                  f"young:{r['domain']}", src_ip=ip, events={"q": r["domain"]},
                                  description=f"{r['domain']} was registered on {registered:%Y-%m-%d} and first looked up "
                                              f"on your network by {ip}. Threshold and on/off: Settings › Threat intel & traps.")

    # --------------------------------------------------------------- canary ---
    async def canary(self, internal, watermark, commit) -> None:
        targets = parse_canaries(self.s.canary_targets)
        last, current = await watermark("canary")
        if not targets:
            await commit("canary", current)
            return
        rows = await db.pool().fetch(
            "SELECT host(src_ip) src, host(dst_ip) dst, dst_port port, coalesce(proto, '') proto, count(*) n, "
            f"{ALLOWED_AGG} passed FROM events WHERE id > $1 AND id <= $2 "
            "AND source IN ('firewall', 'zenarmor', 'suricata') AND src_ip IS NOT NULL AND dst_ip <<= ANY($3::inet[]) "
            "GROUP BY 1, 2, 3, 4", last, current, sorted({str(n) for n, _ in targets}))
        skip = Matcher(self.s.canary_exclude)
        for r in rows:
            ip = ipaddress.ip_address(r["dst"])
            if not any(ip in n and (p is None or p == r["port"]) for n, p in targets) or skip.match(r["src"]):
                continue
            inside = internal(r["src"])
            if self.s.canary_internal_only and not inside:
                continue
            rating = Rating("high" if inside else "medium",
                            "a canary was touched - nothing legitimate uses it, so something is exploring the network"
                            if inside else "an internet address touched a canary", sticky=True)
            target = f"{r['dst']}:{r['port']}" if r["port"] else r["dst"]
            await raise_alert(
                "canary", corroborate(rating, await evidence(r["src"], "canary"), 1),
                f"Canary touched: {r['src']} → {target}", f"canary:{r['src']}:{target}", src_ip=r["src"], dst_ip=r["dst"],
                events={"ip": r["src"]}, count=r["n"],
                description=f"{r['src']} contacted the canary {target} ({r['proto'] or 'ip'}, "
                            f"{'allowed' if r['passed'] else 'blocked'}). Your own scanner? Settings › Threat intel & traps "
                            "› Canary: ignore these sources.")
        await commit("canary", current)

    # ------------------------------------------------------------------ ARP ---
    async def arp(self, internal) -> None:
        if not self.s.arp_watch:
            return
        skip = Matcher(self.s.arp_exclude)
        pool = db.pool()
        for r in await pool.fetch(
                "SELECT host(src_ip) ip, data->>'mac' mac, data->>'interface' intf, count(*) n FROM events "
                "WHERE source = 'arp' AND action = 'arp_conflict' AND ts > now() - interval '15 minutes' GROUP BY 1, 2, 3"):
            if skip.match(r["ip"], r["mac"]):
                continue
            await raise_alert(
                "arp_spoofing", Rating("high", "a device answers for the FIREWALL's own address - classic man-in-the-middle "
                                               "(ARP spoofing), or a badly configured device", sticky=True),
                f"Device {r['mac']} claims the firewall's address {r['ip']}", f"arp_conflict:{r['mac']}:{r['ip']}",
                src_ip=r["ip"], events={"source": "arp"}, count=r["n"], data={"mac": r["mac"]},
                description=f"OPNsense reports that {r['mac']} is using its IP address {r['ip']} on {r['intf'] or '?'}. Find "
                            "that MAC (UniFi › Client Devices, or the switch port) and remove it from the network.")
        for r in await pool.fetch(
                "SELECT host(src_ip) ip, count(*) n, array_agg(DISTINCT data->>'to') macs FROM events WHERE source = 'arp' "
                "AND action = 'arp_move' AND ts > now() - interval '1 hour' AND src_ip IS NOT NULL GROUP BY 1 "
                "HAVING count(*) >= $1", self.s.arp_flips):
            if r["ip"] in ("0.0.0.0", "::") or skip.match(r["ip"], *(r["macs"] or [])):
                continue
            await raise_alert(
                "arp_spoofing", corroborate(Rating("high", "an address keeps moving between devices - ARP spoofing, or "
                                                           "an IP conflict / failover setup"), await evidence(r["ip"], "arp_spoofing"), 1),
                f"{r['ip']} switched between devices {r['n']} times in 1 hour", f"arp_flip:{r['ip']}", src_ip=r["ip"],
                events={"source": "arp", "ip": r["ip"]}, count=r["n"], mode="max", data={"macs": r["macs"]},
                description=f"The MAC address of {r['ip']} changed {r['n']} times in the last hour (MACs: "
                            f"{', '.join(m for m in r['macs'] or [] if m)}). Expected for failover (CARP / VRRP) or a "
                            "repeater: add it under Settings › Threat intel & traps › ARP: ignore.")
        table = await db.get_snapshot("arp") or []
        per_mac: dict[str, set[str]] = defaultdict(set)
        for e in table if isinstance(table, list) else []:
            mac = (e.get("mac") or "").lower()
            if not mac or e.get("permanent") or str(e.get("expires", "")).lower() == "permanent" or e.get("expired"):
                continue
            if e.get("ip") and internal(e["ip"]):
                per_mac[mac].add(e["ip"])
        for mac, addrs in per_mac.items():
            if len(addrs) >= 5 and not skip.match(mac, *addrs):
                await raise_alert(
                    "arp_spoofing", Rating("medium", "one device answers for many addresses - a router / VM host, or ARP "
                                                     "spoofing"),
                    f"Device {mac} holds {len(addrs)} IP addresses", f"arp_many:{mac}", events={"source": "arp"},
                    data={"mac": mac, "ips": sorted(addrs)},
                    description=f"{mac} appears for {', '.join(sorted(addrs)[:12])} in the firewall's ARP table. Normal for "
                                "a router, VPN gateway or VM host with bridged guests: add the MAC under ARP: ignore.")


def parse_canaries(text: str) -> list[tuple[Any, int | None]]:
    out = []
    for part in (text or "").replace("\n", ",").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        port = None
        if part.count(":") == 1:  # IPv4:port
            part, p = part.split(":")
            port = int(p) if p.strip().isdigit() else None
        elif part.startswith("[") and "]:" in part:  # [IPv6]:port
            part, p = part[1:].split("]:")
            port = int(p) if p.isdigit() else None
        try:
            out.append((ipaddress.ip_network(part.strip("[]"), strict=False), port))
        except ValueError:
            continue
    return out


def describe_rule(r: dict[str, Any]) -> str:
    """One line for a port forward / filter rule row of the OPNsense API."""
    def f(*keys: str) -> str:
        for k in keys:
            v = r.get(k)
            if isinstance(v, dict):  # option lists: {"value": {"selected": 1, ...}}
                v = ", ".join(str(x.get("value", k2)) for k2, x in v.items() if isinstance(x, dict) and x.get("selected"))
            if v not in (None, ""):
                return str(v)
        return ""
    parts = [f("action"), f("interface"), f("protocol"), f("source_net", "source"), "→",
             f("destination_net", "destination") + (":" + f("destination_port") if f("destination_port") else ""),
             ("⇒ " + f("target") + (":" + f("local-port", "local_port", "target_port") if f("local-port", "local_port", "target_port") else ""))
             if f("target") else "", f"({f('description', 'descr')})" if f("description", "descr") else "",
             "[disabled]" if str(r.get("enabled", "1")) in ("0", "false") else ""]
    return " ".join(p for p in parts if p).replace("  ", " ")


# port names OPNsense shows in rules (its well-known service names) for the ports worth redirecting
PORT_NAMES = {"domain": 53, "dns": 53, "ntp": 123, "http": 80, "https": 443, "smtp": 25, "ssh": 22, "snmp": 161,
              "syslog": 514, "dot": 853, "domain-s": 853}


def _port(value: str) -> int | None:
    value = value.strip().lower()
    if value.isdigit():
        return int(value)
    if value in PORT_NAMES:
        return PORT_NAMES[value]
    try:
        return socket.getservbyname(value)
    except OSError:
        return None  # an alias name: unknown ports


def nat_redirects(rows: list[dict[str, Any]] | None) -> list[tuple[int, int, str]]:
    """Active port forwards that send a port (range) to the firewall itself / another inside address - the usual
    'force all devices through my resolver / time server' NAT rule: (first port, last port, describe_rule() line)."""
    out = []
    for r in rows or []:
        if not isinstance(r, dict) or str(r.get("enabled", "1")) in ("0", "false") \
                or str(r.get("disabled", "0")) in ("1", "true") or str(r.get("nordr", "0")) in ("1", "true"):
            continue
        port = str(next((r[k] for k in ("destination_port", "destination.port", "dstport") if r.get(k) not in (None, "")), ""))
        lo, sep, hi = port.replace(":", "-").partition("-")
        first = _port(lo) if lo else None
        last = _port(hi) if sep else first
        if first is None or last is None:
            continue
        target = str(r.get("target") or "").strip()
        try:
            addr = ipaddress.ip_address(target)
            if not (addr.is_loopback or is_internal_ip(addr)):
                continue  # redirected to a server on the internet: still leaves your network
        except ValueError:
            if not target:
                continue  # an alias / interface address ("LAN address") counts as local
        out.append((first, last, describe_rule(r)))
    return out


def dns_redirects(rows: list[dict[str, Any]] | None) -> list[str]:
    """Active port forwards that send DNS (port 53) to a local resolver. One describe_rule() line per rule."""
    return [line for lo, hi, line in nat_redirects(rows) if lo <= 53 <= hi]


def exposure_changes(prev: dict[str, str], cur: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    added = [cur[k] for k in cur if k not in prev]
    changed = [f"{prev[k]}  →  {cur[k]}" for k in cur if k in prev and prev[k] != cur[k]]
    removed = [prev[k] for k in prev if k not in cur]
    return added, changed, removed


def opens_inbound(line: str) -> bool:
    """A port forward, or a pass rule on a WAN interface."""
    low = line.lower()
    return "⇒" in line or (low.startswith("pass") and "wan" in low and "[disabled]" not in low)
