"""Privacy mode for the AI analyst: local identifiers are replaced by consistent pseudonyms before anything is sent
to the AI endpoint, and translated back in everything the model returns (its answer and its tool calls).

How it fits in:

* Only the request leaving the server is changed (``ai.Analyst._complete``). Conversations, reports, tool results and
  the logs themselves keep the real values, so turning the mode on or off never breaks an old conversation, and
  every request is pseudonymized as a whole, so the model always sees ONE consistent picture.
* The pseudonyms are remembered in ``ai_pseudonyms`` (real -> fake), so the same device gets the same pseudonym in
  every request, report and conversation, also after a restart.
* Values are replaced by KIND, wherever they appear (columns, raw log lines, JSON, alert titles, the user's own
  question), never per field: a value pseudonymized in one place but real in another would confuse the model.

What is replaced:

* private IPv4 (RFC1918 / CGNAT): the network (first three octets) gets a fake one of the same class, the last octet
  stays (``.1`` is still the gateway) - subnet filters (``<< '10.4.7.0/24'``) keep working.
* your own public addresses (WAN addresses of OPNsense, "Extra internal networks"): documentation addresses
  (203.0.113.x, 198.51.100.x, 192.0.2.x).
* IPv6: unique local (fd..) and your own prefixes (from the OPNsense interfaces) get a fake site prefix
  (``2001:db8:…`` / ``fd..``), the subnet id stays, the interface id is random (it can contain the MAC).
* MAC addresses: the vendor part (first three bytes) stays, the rest is random.
* email addresses.
* names (optional): device host names / UniFi aliases, Wi-Fi names (SSIDs, also neighbouring ones), user names that
  logged in, Unraid server names and your own extra terms (domains, family names ...) become tokens such as
  ``iphone-k7q2``, ``ssid-iot-m3xa``, ``user-p9rd``; a generic word in front (iphone, camera, tv ...) is kept as a hint.

Not replaced (needed for the analysis, and not identifying on their own): external IPs, domains, ports, countries,
container / program names, rule names and signatures.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger(__name__)

ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i: tokens survive being read / retyped

# names that identify nobody and are too common to replace (they would also hit ordinary words in log lines)
GENERIC = {
    "localhost", "unknown", "none", "null", "default", "router", "gateway", "firewall", "opnsense", "pfsense",
    "unraid", "tower", "docker", "server", "switch", "printer", "android", "iphone", "ipad", "macbook", "laptop",
    "desktop", "phone", "tablet", "camera", "television", "nas", "wan", "lan", "dmz", "guest", "home", "office",
    "admin", "administrator", "root", "user", "users", "test", "demo", "support", "operator", "pi", "ubuntu", "debian",
    "centos", "fedora", "oracle", "postgres", "mysql", "ftp", "www", "www-data", "nobody", "git", "backup", "ansible",
    "vagrant", "nagios", "ec2-user", "azureuser", "sshd", "daemon", "system", "service", "local", "wifi", "wlan",
    "iot", "media", "printer", "scanner", "speaker", "chromecast", "esp", "espressif", "raspberrypi", "homeassistant",
    "home-assistant", "unifi", "ubiquiti", "synology", "qnap", "fritz", "fritzbox", "kodi", "plex", "openwrt",
}
# a generic word inside a device name that is kept as a hint about the device type (longest / most specific first)
HOST_HINTS = (
    "iphone", "ipad", "macbook", "imac", "appletv", "android", "galaxy", "pixel", "oneplus", "xiaomi", "huawei",
    "watch", "chromecast", "firetv", "roku", "shield", "echo", "alexa", "nest", "doorbell", "ring", "camera", "cam",
    "printer", "nas", "plug", "bulb", "lamp", "light", "thermostat", "xbox", "playstation", "ps5", "ps4", "nintendo",
    "sonos", "hue", "shelly", "tasmota", "esp", "raspberrypi", "laptop", "desktop", "notebook", "workstation",
    "server", "phone", "tablet", "kindle", "vacuum", "roborock", "tv", "pc",
)
SSID_HINTS = ("iot", "guest", "gast", "kids", "work", "cam", "smart", "mgmt", "vpn")
# only as a whole word ("ernest-pc" is no nest, "spring-laptop" no ring)
SHORT_HINTS = {"tv", "pc", "cam", "esp", "nas", "ps4", "ps5", "hue", "iot", "vpn", "ring", "nest", "echo", "light",
               "plug", "lamp", "watch", "work", "kids", "gast", "smart", "mgmt", "shield"}

PRIVATE4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
DOC4 = ("203.0.113", "198.51.100", "192.0.2")  # documentation ranges: placeholders the model recognises
ULA = ipaddress.ip_network("fc00::/7")
LINK6 = ipaddress.ip_network("fe80::/10")

# --------------------------------------------------------------- patterns ---
_HEX = "[0-9A-Fa-f]"
P_MAC = rf"(?<![0-9A-Fa-f:.-])(?P<mac>{_HEX}{{2}}(?P<sep>[:-])(?:{_HEX}{{2}}(?P=sep)){{4}}{_HEX}{{2}})(?![0-9A-Fa-f:-])"
P_EMAIL = r"(?<![A-Za-z0-9._%+-])(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![A-Za-z0-9-])"
P_ARPA = r"(?<![\w.-])(?P<arpa>(?P<a4>\d{1,3})\.(?P<a3>\d{1,3})\.(?P<a2>\d{1,3})\.(?P<a1>\d{1,3})\.(?i:in-addr\.arpa))"
P_V6M = r"(?<![0-9A-Za-z:])(?P<v6m>::(?i:ffff):(?P<v6m4>\d{1,3}(?:\.\d{1,3}){3}))(?![\d]|\.\d)"
P_IP6 = rf"(?<![0-9A-Za-z:.])(?P<ip6>{_HEX}{{0,4}}(?::{_HEX}{{0,4}}){{2,7}})(?:/(?P<p6>\d{{1,3}}))?(?![0-9A-Za-z:]|\.\d)"
P_IP4 = r"(?<![\d.])(?P<ip4>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<p4>\d{1,2}))?(?!\d|\.\d)"
P_PFX4 = r"(?<![\d.])(?P<pfx4>\d{1,3}\.\d{1,3}\.\d{1,3})\.(?![\d])"  # "192.168.1.x", "192.168.1.%" in SQL
P_DASH4 = r"(?<!\d)(?<!\d-)(?P<dash4>(?:10|172|192|100)-\d{1,3}-\d{1,3}-\d{1,3})(?!\d|-\d)"  # ip-10-0-0-5
BASE_PATTERNS = [P_MAC, P_EMAIL, P_ARPA, P_V6M, P_IP6, P_IP4, P_PFX4, P_DASH4]


def trie_regex(words: list[str]) -> str:
    """One regular expression matching any of ``words`` (longest first) - a trie instead of a plain alternation,
    which stays fast with thousands of names."""
    trie: dict[str, Any] = {}
    for w in words:
        if not w:
            continue
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict[str, Any]) -> str:
        alts = [re.escape(ch) + build(node[ch]) for ch in sorted(k for k in node if k)]
        if not alts:
            return ""
        end = "" in node
        if len(alts) == 1 and not end:
            return alts[0]
        return "(?:" + "|".join(alts) + ")" + ("?" if end else "")

    return build(trie)


def _code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(4))


def _rnd(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def _class4(addr: ipaddress.IPv4Address) -> ipaddress.IPv4Network | None:
    return next((n for n in PRIVATE4 if addr in n), None)


def _hint(name: str, hints: tuple[str, ...]) -> str:
    low = name.lower()
    words = set(re.split(r"[^a-z0-9]+", low))
    for h in hints:
        if (h in words) if h in SHORT_HINTS else (h in low):
            return h
    return ""


def name_fake(category: str, real: str) -> str:
    """A pseudonym for a name: ``iphone-k7q2``, ``host-k7q2``, ``ssid-iot-k7q2``, ``user-k7q2``, ``name-k7q2``,
    ``domain-k7q2.example`` (a domain gets a reserved .example domain, so it still reads as a domain)."""
    code = _code()
    if category == "host":
        return f"{_hint(real, HOST_HINTS) or 'host'}-{code}"
    if category == "ssid":
        h = _hint(real, SSID_HINTS)
        return f"ssid-{h}-{code}" if h else f"ssid-{code}"
    if category == "user":
        return f"user-{code}"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", real.lower()):
        return f"domain-{code}.example"
    return f"name-{code}"


# ----------------------------------------------------------------- store ---
class MemoryStore:
    """Pseudonym storage for tests (the database store below has the same interface)."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], tuple[str, str]] = {}

    async def load(self) -> list[tuple[str, str, str, str]]:
        return [(k, key, r, f) for (k, key), (r, f) in self.rows.items()]

    async def insert(self, kind: str, key: str, real: str, fake: str) -> tuple[str, str] | None:
        """Store (kind, key) -> fake. Returns the stored (real, fake) - an existing one wins - or None when ``fake``
        is already taken by another value (the caller tries another)."""
        if (kind, key) in self.rows:
            return self.rows[(kind, key)]
        if any(f == fake for _, f in self.rows.values()):
            return None
        self.rows[(kind, key)] = (real, fake)
        return real, fake


class DbStore:
    async def load(self) -> list[tuple[str, str, str, str]]:
        from . import db
        rows = await db.pool().fetch("SELECT kind, key, real, fake FROM ai_pseudonyms")
        return [(r["kind"], r["key"], r["real"], r["fake"]) for r in rows]

    async def insert(self, kind: str, key: str, real: str, fake: str) -> tuple[str, str] | None:
        from . import db
        pool = db.pool()
        got = await pool.fetchval("INSERT INTO ai_pseudonyms (kind, key, real, fake) VALUES ($1, $2, $3, $4) "
                                  "ON CONFLICT DO NOTHING RETURNING fake", kind, key, real, fake)
        if got:
            return real, fake
        row = await pool.fetchrow("SELECT real, fake FROM ai_pseudonyms WHERE kind = $1 AND key = $2", kind, key)
        return (row["real"], row["fake"]) if row else None


# --------------------------------------------------------------- mapping ---
class Mapping:
    """All pseudonyms in memory: kind -> key -> (real, fake), and the way back fake -> (kind, key)."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.fwd: dict[str, dict[str, tuple[str, str]]] = {}
        self.rev: dict[str, dict[str, str]] = {}  # kind -> fake (normalised) -> key
        self.loaded = 0.0
        self.lock = asyncio.Lock()

    def _put(self, kind: str, key: str, real: str, fake: str) -> None:
        self.fwd.setdefault(kind, {})[key] = (real, fake)
        self.rev.setdefault(kind, {})[fake.lower()] = key

    async def load(self) -> None:
        self.fwd, self.rev = {}, {}
        for kind, key, real, fake in await self.store.load():
            self._put(kind, key, real, fake)
        self.loaded = time.monotonic()

    def fake(self, kind: str, key: str) -> str | None:
        hit = self.fwd.get(kind, {}).get(key)
        return hit[1] if hit else None

    def real(self, kind: str, fake: str) -> tuple[str, str] | None:
        """(key, real) for a pseudonym."""
        key = self.rev.get(kind, {}).get(fake.lower())
        return (key, self.fwd[kind][key][0]) if key is not None else None

    async def allocate(self, kind: str, key: str, real: str, make: Callable[[int], str]) -> str:
        async with self.lock:
            if (hit := self.fake(kind, key)) is not None:
                return hit
            for attempt in range(200):
                fake = make(attempt)
                if fake.lower() in self.rev.get(kind, {}) or fake.lower() == key:
                    continue
                got = await self.store.insert(kind, key, real, fake)
                if got:
                    self._put(kind, key, got[0], got[1])
                    return got[1]
            raise RuntimeError(f"no free pseudonym for {kind}")


_MAPPING: Mapping | None = None


def mapping() -> Mapping:
    global _MAPPING
    if _MAPPING is None:
        _MAPPING = Mapping(DbStore())
    return _MAPPING


def invalidate() -> None:
    """Forget the cached pseudonyms (after the table was emptied)."""
    global _MAPPING, _DICT
    _MAPPING, _DICT = None, None


# --------------------------------------------------------------- session ---
@dataclass
class Session:
    """One analysis: pseudonymize what goes out (``hide``), translate back what comes in (``reveal``)."""

    mapping: Mapping
    names: dict[str, tuple[str, str]] = field(default_factory=dict)  # lower(name) -> (category, display form)
    own4: set[str] = field(default_factory=set)  # own public IPv4 addresses
    own_nets: list[Any] = field(default_factory=list)  # own networks (Extra internal networks)
    own6: set[str] = field(default_factory=set)  # own IPv6 sites (first 48 bits, exploded)
    memo: dict[str, str] = field(default_factory=dict)
    tokens: dict[tuple, str | None] = field(default_factory=dict)  # matched text -> its replacement (final)

    def __post_init__(self) -> None:
        pats = list(BASE_PATTERNS)
        if self.names:
            pats.append(r"(?<![A-Za-z0-9])(?P<name>(?i:" + trie_regex(sorted(self.names)) + r"))(?![A-Za-z0-9])")
        self._hide_re = re.compile("|".join(pats))
        self._reveal_re: tuple[int, re.Pattern] | None = None

    # ----------------------------------------------------------- hide ---
    def _ip4(self, text: str, prefix: int | None, alloc: Callable) -> str | None:
        try:
            addr = ipaddress.IPv4Address(text)
        except ValueError:
            return None
        net = _class4(addr)
        if net is not None:
            if prefix is not None and prefix <= net.prefixlen and addr == net.network_address:
                return None  # the whole private block (10.0.0.0/8): identifies nobody
            a, b, c, d = text.split(".")
            fake = alloc("net4", f"{int(a)}.{int(b)}.{int(c)}", f"{int(a)}.{int(b)}.{int(c)}", _net4_maker(net))
            return None if fake is None else f"{fake}.{int(d)}"
        if str(addr) in self.own4 or any(addr in n for n in self.own_nets if n.version == 4):
            return alloc("ip4", str(addr), str(addr), lambda _i: f"{secrets.choice(DOC4)}.{_rnd(1, 254)}")
        return None

    def _ip6(self, text: str, alloc: Callable, prefix: int | None = None) -> str | None:
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            return None
        if prefix is not None and prefix < 48:
            return None  # fc00::/7, a provider's /32 ...: identifies nobody
        if addr.ipv4_mapped:
            inner = self._ip4(str(addr.ipv4_mapped), None, alloc)
            return None if inner is None else f"::ffff:{inner}"
        groups = addr.exploded.split(":")
        site = ":".join(groups[:3])
        if addr in LINK6:
            fake_site = site  # fe80:: is the same everywhere; only the interface id (often the MAC) is replaced
        elif addr in ULA or site in self.own6 or any(addr in n for n in self.own_nets if n.version == 6):
            fake_site = alloc("net6", site, site, _ula_maker if addr in ULA else _doc6_maker)
            if fake_site is None:
                return None
        else:
            return None
        if prefix is not None and prefix <= 64:  # a network: fake site + the real subnet id, no host part
            return str(ipaddress.IPv6Address(f"{fake_site}:{groups[3]}::"))
        key = addr.exploded
        fake = alloc("ip6", key, str(addr), lambda _i: str(ipaddress.IPv6Address(
            f"{fake_site}:{groups[3]}:" + ":".join(f"{secrets.randbelow(65536):04x}" for _ in range(4)))))
        return fake

    def _replace(self, m: re.Match, alloc: Callable) -> str | None:
        kind = m.lastgroup
        g = m.groupdict()
        if g.get("mac"):
            raw = g["mac"]
            key = re.sub(r"[^0-9a-f]", "", raw.lower())
            if key in ("000000000000", "ffffffffffff"):
                return None
            fake = alloc("mac", key, raw.lower().replace("-", ":"),
                         lambda _i: key[:6] + "".join(f"{secrets.randbelow(256):02x}" for _ in range(3)))
            return None if fake is None else _format_mac(fake, raw)
        if g.get("email"):
            raw = g["email"]
            return alloc("email", raw.lower(), raw, lambda _i: f"mail-{_code()}@example.net")
        if g.get("arpa"):
            ip = ".".join(g[k] for k in ("a1", "a2", "a3", "a4"))
            fake = self._ip4(ip, None, alloc)
            return None if fake is None else ".".join(reversed(fake.split("."))) + m.group("arpa")[len(ip):]
        if g.get("v6m"):
            fake = self._ip4(g["v6m4"], None, alloc)
            return None if fake is None else m.group("v6m")[:-len(g["v6m4"])] + fake
        if g.get("ip6"):
            fake = self._ip6(g["ip6"], alloc, int(g["p6"]) if g.get("p6") else None)
            return None if fake is None else fake + (f"/{g['p6']}" if g.get("p6") else "")
        if g.get("ip4"):
            fake = self._ip4(g["ip4"], int(g["p4"]) if g.get("p4") else None, alloc)
            return None if fake is None else fake + (f"/{g['p4']}" if g.get("p4") else "")
        if g.get("pfx4"):
            fake = self._ip4(g["pfx4"] + ".0", None, alloc)
            return None if fake is None else fake.rsplit(".", 1)[0] + "."
        if g.get("dash4"):
            fake = self._ip4(g["dash4"].replace("-", "."), None, alloc)
            return None if fake is None else fake.replace(".", "-")
        if kind == "name" or g.get("name"):
            raw = g["name"]
            category, display = self.names.get(raw.lower(), ("name", raw))
            return alloc("name", display.lower(), display, lambda _i: name_fake(category, display))
        return None

    async def hide(self, text: str) -> str:
        """``text`` with every local identifier replaced by its pseudonym."""
        if not text:
            return text
        if text in self.memo:
            return self.memo[text]
        matches = list(self._hide_re.finditer(text))
        if not matches:
            self.memo[text] = text
            return text
        # the same address / name occurs many times: each distinct match is worked out once (per session)
        keyed = [((m.lastgroup, m.group(0)), m) for m in matches]
        todo = {k: m for k, m in keyed if k not in self.tokens}
        need: list[tuple[str, str, str, Callable]] = []

        def plan(kind: str, key: str, real: str, make: Callable) -> str | None:
            hit = self.mapping.fake(kind, key)
            if hit is None:
                need.append((kind, key, real, make))
            return hit

        # two rounds: an IPv6 address needs the pseudonym of its site (allocated in the first round)
        for _round in range(2):
            need.clear()
            for m in todo.values():
                self._replace(m, plan)
            seen = set()
            for kind, key, real, make in need:
                if (kind, key) not in seen:
                    seen.add((kind, key))
                    await self.mapping.allocate(kind, key, real, make)

        def lookup(kind: str, key: str, real: str, make: Callable) -> str | None:
            return self.mapping.fake(kind, key)

        for k, m in todo.items():
            self.tokens[k] = self._replace(m, lookup)
        out, pos = [], 0
        for k, m in keyed:
            rep = self.tokens[k]
            if rep is not None:
                out.append(text[pos:m.start()])
                out.append(rep)
                pos = m.end()
        out.append(text[pos:])
        result = "".join(out)
        self.memo[text] = result
        return result

    async def hide_json(self, value: Any) -> Any:
        if isinstance(value, str):
            return await self.hide(value)
        if isinstance(value, list):
            return [await self.hide_json(v) for v in value]
        if isinstance(value, dict):
            return {await self.hide(k) if isinstance(k, str) else k: await self.hide_json(v) for k, v in value.items()}
        return value

    async def hide_message(self, m: dict[str, Any]) -> dict[str, Any]:
        """A chat message as it may leave the server: its text and its tool call arguments pseudonymized."""
        out = dict(m)
        if isinstance(out.get("content"), str):
            out["content"] = await self.hide(out["content"])
        elif isinstance(out.get("content"), list):  # content parts
            out["content"] = [{**p, "text": await self.hide(p["text"])} if isinstance(p, dict) and isinstance(p.get("text"), str)
                              else p for p in out["content"]]
        if out.get("tool_calls"):
            out["tool_calls"] = [{**c, "function": {**c["function"], "arguments": await self._hide_args(
                c["function"].get("arguments"))}} if isinstance(c, dict) and isinstance(c.get("function"), dict) else c
                for c in out["tool_calls"]]
        return out

    async def _hide_args(self, arguments: Any) -> Any:
        if not isinstance(arguments, str):
            return arguments
        try:
            return json.dumps(await self.hide_json(json.loads(arguments)), ensure_ascii=False)
        except ValueError:
            return await self.hide(arguments)

    # --------------------------------------------------------- reveal ---
    def _reveal_pattern(self) -> re.Pattern:
        names = self.mapping.rev.get("name", {})
        emails = self.mapping.rev.get("email", {})
        version = len(names) + len(emails) * 100003
        if self._reveal_re is None or self._reveal_re[0] != version:
            pats = [P_MAC, P_ARPA, P_V6M, P_IP6, P_IP4, P_PFX4, P_DASH4]
            words = sorted(set(names) | set(emails))
            if words:
                pats.insert(0, r"(?<![A-Za-z0-9])(?P<name>(?i:" + trie_regex(words) + r"))(?![A-Za-z0-9])")
            self._reveal_re = (version, re.compile("|".join(pats)))
        return self._reveal_re[1]

    def _real4(self, text: str) -> str | None:
        try:
            ipaddress.IPv4Address(text)
        except ValueError:
            return None
        hit = self.mapping.real("ip4", text)
        if hit:
            return hit[1]
        a, b, c, d = text.split(".")
        hit = self.mapping.real("net4", f"{int(a)}.{int(b)}.{int(c)}")
        return f"{hit[1]}.{int(d)}" if hit else None

    def _real6(self, text: str) -> str | None:
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            return None
        if addr.ipv4_mapped:
            inner = self._real4(str(addr.ipv4_mapped))
            return None if inner is None else f"::ffff:{inner}"
        hit = self.mapping.real("ip6", str(addr))
        if hit:
            return hit[1]
        groups = addr.exploded.split(":")
        site = self.mapping.real("net6", ":".join(groups[:3]))  # a network (CIDR) or an address in a fake site
        return str(ipaddress.IPv6Address(site[1] + ":" + ":".join(groups[3:]))) if site else None

    def _reveal_one(self, m: re.Match) -> str | None:
        g = m.groupdict()
        if g.get("name"):
            raw = g["name"]
            hit = self.mapping.real("name", raw) or self.mapping.real("email", raw)
            return hit[1] if hit else None
        if g.get("mac"):
            hit = self.mapping.real("mac", re.sub(r"[^0-9a-f]", "", g["mac"].lower()))
            return _format_mac(hit[0], g["mac"]) if hit else None
        if g.get("arpa"):
            ip = ".".join(g[k] for k in ("a1", "a2", "a3", "a4"))
            real = self._real4(ip)
            return None if real is None else ".".join(reversed(real.split("."))) + m.group("arpa")[len(ip):]
        if g.get("v6m"):
            real = self._real4(g["v6m4"])
            return None if real is None else m.group("v6m")[:-len(g["v6m4"])] + real
        if g.get("ip6"):
            real = self._real6(g["ip6"])
            return None if real is None else real + (f"/{g['p6']}" if g.get("p6") else "")
        if g.get("ip4"):
            real = self._real4(g["ip4"])
            return None if real is None else real + (f"/{g['p4']}" if g.get("p4") else "")
        if g.get("pfx4"):
            real = self._real4(g["pfx4"] + ".0")
            return None if real is None else real.rsplit(".", 1)[0] + "."
        if g.get("dash4"):
            real = self._real4(g["dash4"].replace("-", "."))
            return None if real is None else real.replace(".", "-")
        return None

    def reveal(self, text: str) -> str:
        """The model's text with every pseudonym translated back to the real value."""
        if not text:
            return text
        return self._reveal_pattern().sub(lambda m: self._reveal_one(m) or m.group(0), text)

    def reveal_json(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.reveal(value)
        if isinstance(value, list):
            return [self.reveal_json(v) for v in value]
        if isinstance(value, dict):
            return {self.reveal(k) if isinstance(k, str) else k: self.reveal_json(v) for k, v in value.items()}
        return value

    def reveal_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        out = dict(msg)
        if isinstance(out.get("content"), str):
            out["content"] = self.reveal(out["content"])
        if out.get("tool_calls"):
            calls = []
            for c in out["tool_calls"]:
                fn = dict(c.get("function") or {})
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        fn["arguments"] = json.dumps(self.reveal_json(json.loads(args)), ensure_ascii=False)
                    except ValueError:
                        fn["arguments"] = self.reveal(args)
                calls.append({**c, "function": fn})
            out["tool_calls"] = calls
        return out


def _format_mac(hex12: str, like: str) -> str:
    """12 hex digits written the way ``like`` was (separator and case)."""
    h = re.sub(r"[^0-9a-fA-F]", "", hex12).lower()
    sep = "-" if "-" in like else ":"
    out = sep.join(h[i:i + 2] for i in range(0, 12, 2))
    return out.upper() if like.isupper() else out


def _net4_maker(net: ipaddress.IPv4Network) -> Callable[[int], str]:
    """A fake /24 of the same private class (192.168.x stays 192.168.y)."""

    def make(attempt: int) -> str:
        if net.prefixlen == 16 and attempt < 120:  # 192.168.0.0/16: 256 networks, then fall back to 10.x
            return f"192.168.{_rnd(0, 255)}"
        if net.prefixlen == 12:
            return f"172.{_rnd(16, 31)}.{_rnd(0, 255)}"
        if net.prefixlen == 10:
            return f"100.{_rnd(64, 127)}.{_rnd(0, 255)}"
        return f"10.{_rnd(0, 255)}.{_rnd(0, 255)}"

    return make


def _ula_maker(_attempt: int) -> str:
    return f"fd{secrets.randbelow(256):02x}:{secrets.randbelow(65536):04x}:{secrets.randbelow(65536):04x}"


def _doc6_maker(_attempt: int) -> str:
    return f"2001:0db8:{secrets.randbelow(65536):04x}"


# ------------------------------------------------------------ dictionary ---
@dataclass
class _Dict:
    names: dict[str, tuple[str, str]]
    own4: set[str]
    own6: set[str]
    built: float
    key: tuple


_DICT: _Dict | None = None
REFRESH = 600  # seconds: new devices / names are picked up after at most this long


def _clean_name(value: Any) -> str:
    v = str(value or "").strip()
    if not v or re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]*:[0-9a-fA-F:]*|[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", v):
        return ""
    return v


_RESERVED: set[str] | None = None


def reserved_words() -> set[str]:
    """Words of the AI's own instructions, the database schema and the tool output (column names, JSON keys, log
    sources ...): a device or user called "message" or "source" must not turn JSON keys into pseudonyms."""
    global _RESERVED
    if _RESERVED is None:
        from . import ai
        text = ai.SYSTEM_PROMPT + ai.SCHEMA_DOC + json.dumps(ai.TOOLS)
        _RESERVED = {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", text)} | {
            "rows", "row_count", "src", "dst", "error", "first", "last", "peer", "comments", "comment", "by", "at"}
    return _RESERVED


def build_names(settings: Any, hosts: list[str], ssids: list[str], users: list[str]) -> dict[str, tuple[str, str]]:
    """lower(name) -> (category, display form). Own terms first, then user names, Wi-Fi names and host names; generic
    names and the "never replace" list are left out."""
    keep = {k.strip().lower() for k in re.split(r"[,\n]+", getattr(settings, "ai_privacy_keep", "") or "") if k.strip()}
    out: dict[str, tuple[str, str]] = {}
    reserved = reserved_words()

    def add(category: str, value: Any, min_len: int = 3, generic_ok: bool = False) -> None:
        v = _clean_name(value)
        low = v.lower()
        if len(v) < min_len or low in keep or low in out or ((low in GENERIC or low in reserved) and not generic_ok):
            return
        out[low] = (category, v)
        if category != "term":  # the same name as JSON writes it (escaped quotes, ö ...), same pseudonym
            for variant in (json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1]):
                if variant.lower() not in out:
                    out[variant.lower()] = (category, v)

    for t in re.split(r"[,\n]+", getattr(settings, "ai_privacy_terms", "") or ""):
        add("term", t.strip(), min_len=2, generic_ok=True)
    if getattr(settings, "ai_privacy_names", True):
        for u in users:
            add("user", u)
        for s in ssids:
            add("ssid", s)
        for h in hosts:
            h = _clean_name(h)
            if h.startswith("OPNsense ("):  # names Looking Glass made up for the firewall's own interfaces
                continue
            if "." in h and " " not in h:  # johns-iphone.home.lan: the name itself (the rest is the local domain)
                h = h.split(".", 1)[0]
            add("host", h)
    return out


async def _collect(settings: Any) -> tuple[list[str], list[str], list[str], set[str], set[str]]:
    from . import db
    pool = db.pool()
    hosts = [r["hostname"] for r in await pool.fetch(
        "SELECT DISTINCT hostname FROM devices WHERE hostname IS NOT NULL AND coalesce(name_source, '') <> 'opnsense'")]
    hosts += [r["name"] for r in await pool.fetch("SELECT name FROM unraid_servers")]
    users = [r["username"] for r in await pool.fetch(
        "SELECT DISTINCT username FROM events WHERE username IS NOT NULL AND username <> '' "
        "AND (action IN ('login_success', 'login_ok') OR source = 'vpn') LIMIT 5000")]
    users += [r["username"] for r in await pool.fetch("SELECT username FROM users")]
    ssids: list[str] = []
    clients = await db.get_snapshot("unifi:clients") or []
    for c in clients if isinstance(clients, list) else []:
        if isinstance(c, dict):
            hosts += [c.get("alias") or "", c.get("hostname") or ""]
            ssids.append(c.get("ssid") or "")
    for d in await db.get_snapshot("unifi:devices") or []:
        if isinstance(d, dict):
            ssids += [s for s in d.get("ssids") or [] if isinstance(s, str)]
    for r in await db.get_snapshot("unifi:rogue") or []:
        if isinstance(r, dict):
            ssids.append(r.get("essid") or "")
    own4, own6 = set(), set()
    stats = await db.get_snapshot("interfaces") or {}
    for v in stats.values() if isinstance(stats, dict) else []:
        addr = str(v.get("address") or "").split("%")[0].split("/")[0] if isinstance(v, dict) else ""
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global:
            own4.add(str(ip))
        elif ip.version == 6 and ip.is_global:
            own6.add(":".join(ip.exploded.split(":")[:3]))
    return hosts, ssids, users, own4, own6


async def session(settings: Any, store_mapping: Mapping | None = None) -> Session:
    """A privacy session with the current names, own addresses and pseudonyms (cached for a few minutes)."""
    global _DICT
    from .parsers.common import parse_networks
    mp = store_mapping or mapping()
    if not mp.loaded or time.monotonic() - mp.loaded > REFRESH:
        async with mp.lock:
            await mp.load()
    key = (getattr(settings, "ai_privacy_names", True), getattr(settings, "ai_privacy_terms", ""),
           getattr(settings, "ai_privacy_keep", ""))
    if _DICT is None or _DICT.key != key or time.monotonic() - _DICT.built > REFRESH:
        hosts, ssids, users, own4, own6 = await _collect(settings)
        _DICT = _Dict(build_names(settings, hosts, ssids, users), own4, own6, time.monotonic(), key)
    # own addresses ever seen stay own (a WAN address that changed still appears in older logs)
    own4 = _DICT.own4 | set(mp.fwd.get("ip4", {}))
    own6 = _DICT.own6 | {k for k in mp.fwd.get("net6", {}) if not ipaddress.IPv6Address(k + "::") in ULA}
    nets = [n for n in parse_networks(getattr(settings, "internal_networks", "") or "")
            if not (n.version == 4 and _class4(n.network_address))]
    return Session(mp, _DICT.names, own4, nets, own6)


PROMPT_NOTE = """
PRIVACY MODE is on: local identifiers in everything you see are consistent pseudonyms, the user sees your answer with
the real values. Private IPv4 networks are renumbered per /24 within the same private range (the last octet is real,
so .1 is still the gateway). The network's own public addresses appear as 203.0.113.x / 198.51.100.x / 192.0.2.x,
its own IPv6 prefixes as 2001:db8:… (unique local stays fd…). MAC addresses keep their real vendor part (first three
bytes). Device, Wi-Fi and user names appear as tokens such as host-k7q2, iphone-k7q2, ssid-iot-k7q2, user-k7q2,
domain-k7q2.example (the word before the code is a real hint about the device / network type); emails as
mail-k7q2@example.net. Use these values exactly as given - in tool calls and SQL too (also CIDR filters such as
<< '10.20.30.0/24'): they are translated automatically. Never try to guess or reconstruct real values, and do not
match on fragments of a pseudonym (LIKE '%k7q2%' finds nothing); a device type hint word (LIKE '%iphone%') works.
"""
