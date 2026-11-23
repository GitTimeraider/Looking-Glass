"""Cross-source rules: what SWAG / CrowdSec (Docker) / fail2ban / the honeypot see, tied to what the OPNsense firewall
and the Unraid containers see. Each source on its own says little: an exploit attempt on the web proxy is background
noise, an outbound connection is normal, a container restart happens. Together they tell a story.

* ``proxy_callback`` - a device inside connects OUT to an address that attacked the web proxy shortly before (web attack
  pattern, honeypot, CrowdSec, fail2ban): how a working exploit shows itself (reverse shell, payload download, stolen
  data sent home). The firewall sees the connection, SWAG saw the attack.
* ``ban_bypass`` - an address SWAG's CrowdSec / fail2ban banned (or that touched a honeypot) is still let in by the
  OPNsense firewall to OTHER services: those bans only work inside the web proxy, the rest of what you forward is open
  to it.
* ``web_container_trouble`` - a site answered an attack successfully (2xx / 3xx) and soon after its Unraid container
  started crashing, became unhealthy, stopped or logged errors.

Only internet addresses count as attackers; an attacker that is inside the network already raises a high alert of its
own (web attack, honeypot, CrowdSec, fail2ban).
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable

from . import db
from .config import Settings
from .detections import ALLOWED_ROW, Rating, raise_alert

# web request tags that are an attack (not a scanner user agent or an unknown path); honeypot = a trap was touched
ATTACK_TAGS = ["rce", "sqli", "path_traversal", "sensitive_file", "xss", "honeypot"]
# tags of a web attack that, answered successfully, may have worked (honeypot traps answer what you set, often 200)
HARM_TAGS = ["rce", "sqli", "path_traversal", "sensitive_file"]
ATTACK_HOURS = 24  # how far back an address counts as an attacker
CALLBACK_SHARED = 3  # contacted by this many devices inside: a popular service (CDN, cloud), not a call home
CONTAINER_RULES = ("unraid_container_restarting", "unraid_container_unhealthy", "unraid_container_down",
                   "unraid_container_errors")
CONTAINER_WINDOW = 60  # minutes between a successful web attack and the container's trouble
MAX_IPS = 5000  # addresses looked up per run at most (a flood of new firewall lines is read over several runs)
REPLY_HOURS = 2  # how far back an inbound connection from the attacker makes a mirrored outbound packet its reply
# a firewall line that can be the start of a connection: not TCP (no flags logged) or a TCP SYN without ACK. ACK, PSH,
# FIN, RST or SYN+ACK packets belong to a session that already exists - for a server that is the attacker's own session
OPENS_SQL = "(coalesce(data->>'tcpflags', '') = '' OR (data->>'tcpflags' LIKE '%S%' AND data->>'tcpflags' NOT LIKE '%A%'))"

# what makes an address an attacker of the web proxy, per event (SQL)
ATTACKER_SQL = (
    "((source = 'nginx' AND jsonb_typeof(data->'tags') = 'array' AND data->'tags' ?| $2::text[]) "
    " OR (source = 'nginx' AND action IN ('bouncer_block', 'waf_block')) "
    " OR (source = 'crowdsec' AND action IN ('alert', 'ban', 'captcha')) "
    " OR (source = 'fail2ban' AND action = 'ban'))")
# what makes an address banned / flagged on the web proxy (its bans do not reach the firewall)
BANNED_SQL = (
    "((source = 'crowdsec' AND program = 'crowdsec-lapi' AND action IN ('ban', 'captcha')) "
    " OR (source = 'nginx' AND action = 'bouncer_block') "
    " OR (source = 'fail2ban' AND action = 'ban') "
    " OR (source IN ('nginx', 'fail2ban') AND data->>'honeypot' = 'true'))")
# a label per signal, for the alert text
WHY_SQL = (
    "CASE WHEN data->>'honeypot' = 'true' THEN 'honeypot' "
    "WHEN source = 'crowdsec' THEN 'CrowdSec' || CASE WHEN program = 'crowdsec-lapi' THEN ' (SWAG)' ELSE ' (OPNsense)' END "
    "  || ': ' || coalesce(data->>'scenario', data->>'reason', action) "
    "WHEN source = 'fail2ban' THEN 'fail2ban ban (' || coalesce(data->>'jail', '?') || ')' "
    "WHEN action = 'bouncer_block' THEN 'CrowdSec bouncer block' WHEN action = 'waf_block' THEN 'WAF block' "
    "ELSE 'web attack (' || (SELECT string_agg(t, ', ') FROM jsonb_array_elements_text(data->'tags') t "
    "                        WHERE t = ANY($2::text[])) || ')' END")


def ports(text: str) -> list[int]:
    """'80, 443' -> [80, 443] (anything else in the list is skipped)."""
    out = []
    for p in (text or "").replace(";", ",").split(","):
        p = p.strip()
        if p.isdigit() and 0 < int(p) < 65536:
            out.append(int(p))
    return out


def container_matches(container: str, domain: str | None) -> bool:
    """A site belongs to a container when a label of its host name is the container's name: SWAG's proxy confs are
    named after the container (nextcloud.subdomain.conf -> nextcloud.example.com -> container nextcloud)."""
    if not domain or not container:
        return False
    c = container.lower()
    labels = domain.lower().split(".")
    return c in labels or labels[0].replace("-", "") == c.replace("-", "").replace("_", "")


class CrossLink:
    def __init__(self, settings: Settings, internal: Callable[[Any], bool]) -> None:
        self.settings = settings
        self.internal = internal

    async def attackers(self, ips: list[str], sql: str, hours: int = ATTACK_HOURS) -> dict[str, dict[str, Any]]:
        """Of ``ips``, the internet addresses that the web proxy side flagged in the last ``hours``: ip -> first / last
        time, what (labels), the sites and how many harmful requests got a successful answer. Addresses that forward
        for others (X-Forwarded-For: a CDN or a proxy in front of SWAG) are left out - they are not the attacker."""
        ips = [ip for ip in dict.fromkeys(ips) if ip and not self.internal(ip)][:MAX_IPS]
        if not ips:
            return {}
        rows = await db.pool().fetch(
            "SELECT host(src_ip) ip, min(ts) first, max(ts) last, array_agg(DISTINCT why) whys, "
            "array_agg(DISTINCT domain) FILTER (WHERE domain IS NOT NULL) sites, "
            "count(*) FILTER (WHERE ok) through, bool_or(xff) xff FROM ("
            f"  SELECT src_ip, ts, domain, {WHY_SQL} why, "
            "   source = 'nginx' AND action ~ '^http_[23]' AND jsonb_typeof(data->'tags') = 'array' "
            "     AND data->'tags' ?| $4::text[] ok, "
            "   source = 'nginx' AND data->>'x_forwarded_for' IS NOT NULL xff "
            f"  FROM events WHERE src_ip = ANY($1::inet[]) AND ts > now() - make_interval(hours => $3) AND {sql}) t "
            "GROUP BY 1", ips, ATTACK_TAGS, hours, HARM_TAGS)
        return {r["ip"]: {**dict(r), "whys": sorted(w for w in r["whys"] if w), "sites": sorted(r["sites"] or [])}
                for r in rows if not r["xff"]}

    async def firewall_view(self, ip: str, hours: int = ATTACK_HOURS) -> list[str]:
        """What the OPNsense side knows about an internet address that attacks the web proxy: Suricata signatures,
        Q-Feeds / blocklist hits and scan alerts. Empty = the firewall has nothing on it."""
        pool = db.pool()
        r = await pool.fetchrow(
            "SELECT count(*) FILTER (WHERE source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject')) ids, "
            "count(*) FILTER (WHERE source = 'qfeeds' OR (source = 'firewall' AND data->>'blocklist' IS NOT NULL)) listed, "
            "count(*) FILTER (WHERE source = 'firewall' AND action IN ('block', 'drop')) fw_blocked, "
            "count(DISTINCT dst_port) FILTER (WHERE source = 'firewall') fw_ports "
            "FROM events WHERE src_ip = $1::inet AND ts > now() - make_interval(hours => $2)", ip, hours)
        scans = [a["rule"] for a in await pool.fetch(
            "SELECT DISTINCT rule FROM alerts WHERE src_ip = $1::inet AND rule IN ('port_scan', 'host_sweep', "
            "'threat_intel_inbound') AND last_seen > now() - make_interval(hours => $2) ORDER BY 1", ip, hours)]
        out = []
        if r and r["ids"]:
            out.append(f"{r['ids']} Suricata hit(s)")
        if r and r["listed"]:
            out.append(f"on a blocklist (Q-Feeds / CrowdSec, {r['listed']} hit(s))")
        if scans:
            out.append("alert(s): " + ", ".join(s.replace("_", " ") for s in scans))
        elif r and r["fw_blocked"] and r["fw_ports"] >= 5:
            out.append(f"the firewall blocked it on {r['fw_ports']} ports")
        return out

    # ------------------------------------------------------------------------------------------------------------
    async def callbacks(self, last: int, current: int) -> None:
        """A device inside connects out to an address that attacked the web proxy before (proxy_callback).

        Only connections the device OPENS count. Packets that answer a connection the attacker opened (a TCP packet
        with ACK / without SYN, or one that mirrors an inbound connection from the attacker: our port = the port it
        connected to, its port = the port it came from) are the server's replies: when a ban cuts off the attacker
        mid-session the firewall drops those replies as a state violation, which is not a call home."""
        pool = db.pool()
        rows = await pool.fetch(
            "SELECT host(src_ip) src, host(dst_ip) dst FROM events WHERE id > $1 AND id <= $2 AND source = 'firewall' "
            f"AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND {OPENS_SQL} GROUP BY 1, 2", last, current)
        rows = [r for r in rows if self.internal(r["src"]) and not self.internal(r["dst"])]
        bad = await self.attackers([r["dst"] for r in rows], ATTACKER_SQL)
        if not bad:
            return
        pairs = [(r["src"], r["dst"]) for r in rows if r["dst"] in bad]
        rows = await pool.fetch(
            "SELECT host(o.src_ip) src, host(o.dst_ip) dst, min(o.ts) first, max(o.ts) last, count(*) n, "
            "array_agg(DISTINCT o.dst_port) FILTER (WHERE o.dst_port IS NOT NULL) dports, "
            f"count(*) FILTER (WHERE {ALLOWED_ROW}) passed "
            "FROM events o JOIN unnest($3::inet[], $4::inet[]) p(s, d) ON o.src_ip = p.s AND o.dst_ip = p.d "
            f"WHERE o.id > $1 AND o.id <= $2 AND o.source = 'firewall' AND {OPENS_SQL} "
            # the mirror of an inbound connection from the attacker = a reply on its session (UDP, or no flags logged)
            "AND NOT (o.src_port IS NOT NULL AND o.dst_port IS NOT NULL AND EXISTS (SELECT 1 FROM events i "
            "  WHERE i.source = 'firewall' AND i.src_ip = o.dst_ip AND i.dst_ip = o.src_ip AND i.src_port = o.dst_port "
            "  AND i.dst_port = o.src_port AND i.ts BETWEEN o.ts - make_interval(hours => $5) AND o.ts)) "
            "GROUP BY 1, 2", last, current, [p[0] for p in pairs], [p[1] for p in pairs], REPLY_HOURS)
        # a destination many devices of yours talk to is a popular service (CDN / cloud) that also hosts scanners
        shared = {r["dst"]: r["n"] for r in await pool.fetch(
            "SELECT host(dst_ip) dst, count(DISTINCT src_ip) n FROM events WHERE dst_ip = ANY($1::inet[]) "
            "AND source = 'firewall' AND ts > now() - make_interval(hours => $2) GROUP BY 1",
            list(bad), ATTACK_HOURS)}
        for r in rows:
            a = bad.get(r["dst"])
            if not a or r["last"] < a["first"] or shared.get(r["dst"], 0) >= CALLBACK_SHARED:
                continue  # not an attacker, the connection came before the attack, or a shared service
            src, dst = r["src"], r["dst"]
            after = r["first"] - a["first"]
            rating = Rating("high", f"{src} connected OUT to {dst}, an address that attacked your web proxy "
                                    f"{_ago(after)} before - how a working exploit shows itself (reverse shell, payload "
                                    "download, data sent home)", sticky=True)
            if r["passed"]:
                rating.up("the firewall let the connection through")
            if a["through"]:
                rating.why.append(f"{a['through']} attack request(s) got a successful answer from the web proxy")
            dports = ", ".join(str(p) for p in sorted(r["dports"] or [])[:8]) or "?"
            await raise_alert(
                "proxy_callback", rating, f"{src} connected to {dst}, which attacked your web proxy before",
                f"callback:{src}:{dst}", src_ip=src, dst_ip=dst, count=r["n"], span=(a["first"], r["last"]),
                events={"ip": dst}, blocked=not r["passed"] and "the firewall blocked the connection",
                data={"attacker": dst, "attack": a["whys"][:10], "sites": a["sites"][:10]},
                description=f"First {dst} attacked the web proxy ({'; '.join(a['whys'][:6])}"
                            + (f" on {', '.join(a['sites'][:5])}" if a["sites"] else "") + "), then "
                            f"{src} opened {r['n']} connection(s) to it (port {dports}, {r['passed']} allowed). Servers do "
                            "not contact the addresses that attack them. Check the device / container behind the attacked "
                            "site (its log around that time, new processes or files), block the address (Blocked "
                            "addresses) and update the attacked application.")

    async def ban_bypass(self, last: int, current: int) -> None:
        """An address SWAG banned or that touched a honeypot still gets through OPNsense to other services."""
        pool = db.pool()
        proxy = ports(getattr(self.settings, "swag_proxy_ports", "80,443"))
        rows = await pool.fetch(
            "SELECT host(src_ip) src, min(ts) first, max(ts) last, count(*) n, "
            "array_agg(DISTINCT dst_port) dports, array_agg(DISTINCT host(dst_ip)) dsts FROM events "
            "WHERE id > $1 AND id <= $2 AND source = 'firewall' AND action = 'pass' AND src_ip IS NOT NULL "
            "AND dst_port IS NOT NULL AND NOT (dst_port = ANY($3::int[])) GROUP BY 1", last, current, proxy)
        rows = [r for r in rows if not self.internal(r["src"])]
        flagged = await self.attackers([r["src"] for r in rows], BANNED_SQL)
        if not flagged:
            return
        blocked = {r["a"] for r in await pool.fetch(
            "SELECT host(x) a FROM unnest($1::inet[]) x JOIN blocks b ON x <<= b.ip WHERE b.status = 'active'",
            list(flagged))}
        for r in rows:
            a = flagged.get(r["src"])
            if not a or r["last"] < a["first"] or r["src"] in blocked:
                continue
            ip = r["src"]
            dports = ", ".join(str(p) for p in sorted(r["dports"])[:10])
            rating = Rating("medium", "an address the web proxy banned / caught in a trap still reaches other services "
                                      "through the OPNsense firewall - those bans only work inside SWAG", sticky=True)
            await raise_alert(
                "ban_bypass", rating, f"{ip} is banned on SWAG but the firewall still lets it in (port {dports})",
                f"bypass:{ip}", src_ip=ip, count=r["n"], span=(a["first"], r["last"]),
                events={"source": "firewall", "ip": ip}, data={"flagged": a["whys"][:10], "ports": sorted(r["dports"])[:20]},
                description=f"{ip} was flagged by the web proxy ({'; '.join(a['whys'][:6])}), yet afterwards the "
                            f"OPNsense firewall passed {r['n']} connection(s) from it to port {dports} on "
                            f"{', '.join(sorted(r['dsts'])[:5])}. Block it on OPNsense (Blocked addresses › Block, or "
                            "the automatic blocking), so every forwarded service is shut for it, not only the web "
                            "proxy. Ports that are the web proxy itself: Settings › SWAG & CrowdSec › Ports forwarded "
                            "to SWAG.")

    async def container_trouble(self) -> None:
        """A site answered an attack successfully, then its container got into trouble (web_container_trouble)."""
        pool = db.pool()
        trouble = await pool.fetch(
            "SELECT id, rule, title, created_at, data->>'container' AS container FROM alerts "
            "WHERE rule = ANY($1::text[]) AND status <> 'closed' AND created_at > now() - interval '3 hours' "
            "AND data->>'container' IS NOT NULL", list(CONTAINER_RULES))
        by_container: dict[str, list[Any]] = {}
        for t in trouble:
            by_container.setdefault(t["container"], []).append(t)
        for container, alerts in by_container.items():
            start = min(t["created_at"] for t in alerts)
            hits = await pool.fetch(
                "SELECT host(src_ip) ip, domain, count(*) n, min(ts) first, max(ts) last, "
                "array_agg(DISTINCT data->>'path') paths, bool_or(data->>'x_forwarded_for' IS NOT NULL) xff FROM events "
                "WHERE source = 'nginx' AND ts BETWEEN $1 AND $2 AND src_ip IS NOT NULL AND domain IS NOT NULL "
                "AND action ~ '^http_[23]' AND jsonb_typeof(data->'tags') = 'array' AND data->'tags' ?| $3::text[] "
                "GROUP BY 1, 2", start - timedelta(minutes=CONTAINER_WINDOW), max(t["created_at"] for t in alerts),
                HARM_TAGS)
            hits = [h for h in hits if container_matches(container, h["domain"]) and not self.internal(h["ip"])]
            if not hits:
                continue
            hits.sort(key=lambda h: (h["xff"], -h["n"]))  # a CDN / proxy forwarding for others is not the attacker
            ip = hits[0]["ip"]
            n = sum(h["n"] for h in hits)
            paths = sorted({p for h in hits for p in h["paths"] or [] if p})[:5]
            what = "; ".join(sorted({t["title"] for t in alerts}))[:300]
            rating = Rating("high", f"{n} attack request(s) on {hits[0]['domain']} got a successful answer, and within "
                                    f"{CONTAINER_WINDOW} minutes its container {container} got into trouble", sticky=True)
            await raise_alert(
                "web_container_trouble", rating, f"Attack on {hits[0]['domain']}, then trouble in container {container}",
                f"webctr:{container}", src_ip=ip, count=n, span=(min(h["first"] for h in hits), max(h["last"] for h in hits)),
                events={"source": "nginx", "ip": ip}, data={"container": container, "alerts": [t["id"] for t in alerts],
                                                            "attackers": sorted({h["ip"] for h in hits})[:10]},
                description=f"Successful answers to attack requests from {', '.join(sorted({h['ip'] for h in hits})[:5])} "
                            f"({', '.join(paths)}), then: {what}. A crash, failing health check or burst of errors right "
                            "after an exploit attempt can mean it hit something. Read the container's log around that "
                            "time (Unraid › Docker › logs), check it for new files / processes and update the "
                            "application. Same name? The container is matched to the site by host name "
                            "(nextcloud.example.com → nextcloud).")


def _ago(td: timedelta) -> str:
    s = max(0, int(td.total_seconds()))
    return f"{s // 3600} h {s % 3600 // 60} min" if s >= 3600 else f"{max(1, s // 60)} min"
