"""Container vulnerability scanning: Grype + Syft, CISA KEV, EPSS, NVD and OSV, plus own app-version checks.

How it works (Settings › Container vulnerabilities; results on the Vulnerabilities page):

* Inventory: every container of every Unraid server (Unraid API) plus the extra images you list. With a Docker API
  (docker-socket-proxy with CONTAINERS=1 and IMAGES=1) the exact image digest that runs is known, so exactly that image
  is scanned - also when the tag moved on since. Containers on one image are scanned once.
* SBOM: Syft lists every package in the image (OS packages, PHP / npm / Python / Go / Java / Rust libraries, and
  binaries such as php, httpd or nginx that were compiled from source) - from the registry by digest, or exported
  through the Docker API. Built again when the digest changes and every ``vuln_rescan_days`` days.
* Matching: Grype matches the stored SBOMs against its vulnerability database (NVD, GitHub advisories, the Linux
  distributions' own trackers) every ``vuln_recheck_hours`` hours - without downloading the images again, so a CVE
  published today for an image you pulled months ago shows up the same day.
* Enrichment: CISA KEV (actively exploited), FIRST EPSS (chance of exploitation in the next 30 days) and a CVSS
  lookup (NVD) for findings without a score. Own checks read the version of the application itself (an image label,
  environment variable, the tag or a package) and look it up in OSV - for the app's own CVEs that package scanners
  miss.
* Every address and response format is editable (``vuln_sources``, ``vuln_app_checks``); each one that fails is shown
  with its error on the Vulnerabilities page, and a problem that leaves you blind (no scanner, outdated database, an
  image that cannot be scanned, a source that keeps failing) raises its own alert, closed by itself once it works.
"""
from __future__ import annotations

import asyncio
import fnmatch
import gzip
import hashlib
import json
import logging
import math
import os
import re
import shlex
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from . import db
from .config import Settings
from .detections import Rating, close_alerts, raise_alert

log = logging.getLogger(__name__)

RULE = "container_vulnerable"
PROBLEM_RULE = "vuln_scan_problem"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SOURCE_KINDS = {
    "kev": "list of actively exploited CVEs (CISA KEV)",
    "epss": "exploit prediction scores (FIRST EPSS)",
    "cvss": "CVSS score of a CVE without one (NVD)",
    "osv": "OSV query API for the app checks",
}
FORMATS = ("json", "csv", "text")
USER_AGENT = "Looking-Glass (self-hosted security monitor)"
# a source of this kind failing this long raises a 'vulnerability scan problem' alert
SOURCE_GRACE = {"kev": 2 * 86400, "epss": 3 * 86400, "cvss": 3 * 86400, "osv": 2 * 86400}
KEV_HOURS, EPSS_HOURS, CVSS_DAYS, UPDATE_CHECK_HOURS = 24, 24, 14, 12
CVSS_LOOKUPS_PER_RUN = 40
SEVERITY_SCORE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "moderate": 4.0, "low": 0.1, "negligible": 0.0}
LEVELS = ("info", "low", "medium", "high", "critical")


# ------------------------------------------------------------------ helpers ---
def jpath(obj: Any, path: str) -> list[Any]:
    """Values at a small JSON path: ``a.b[].c`` - dots go into objects, ``[]`` into every list item, ``*`` into every
    value of an object, ``[2]`` takes one item. Missing parts give no values (never an error)."""
    cur = [obj]
    for part in [p for p in path.strip().removeprefix("$").split(".") if p]:
        m = re.fullmatch(r"([^\[\]]*)((?:\[\d*\])*)", part)
        if not m:
            return []
        name, idx = m.group(1), re.findall(r"\[(\d*)\]", m.group(2))
        nxt: list[Any] = []
        for v in cur:
            if name == "*":
                nxt.extend(v.values() if isinstance(v, dict) else [])
            elif name:
                if isinstance(v, dict) and name in v:
                    nxt.append(v[name])
            else:
                nxt.append(v)
        for i in idx:
            out: list[Any] = []
            for v in nxt:
                if isinstance(v, list):
                    if i == "":
                        out.extend(v)
                    elif int(i) < len(v):
                        out.append(v[int(i)])
            nxt = out
        cur = nxt
    return cur


def number(v: Any) -> float | None:
    try:
        f = float(str(v).strip().rstrip("%")) / (100 if str(v).strip().endswith("%") else 1)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def decode(body: bytes) -> str:
    """Response text; gzip-compressed downloads (epss_scores-current.csv.gz) are unpacked."""
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return body.decode("utf-8", "replace")


def csv_rows(text: str) -> list[dict[str, str]]:
    """CSV with a header line; lines starting with # before it (EPSS: #model_version...) are skipped."""
    import csv
    import io
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    return list(csv.DictReader(io.StringIO("\n".join(lines))))


@dataclass
class Source:
    kind: str
    url: str
    method: str = "GET"
    fmt: str = ""          # json | csv | text ('' = the kind's default)
    args: list[str] = field(default_factory=list)
    line: int = 0

    def label(self) -> str:
        u = httpx.URL(self.url.replace("{cves}", "x").replace("{cve}", "x"))
        return f"{u.host}{u.path}"


def parse_sources(text: str) -> dict[str, list[Source]]:
    """Settings › Container vulnerabilities › Sources, one per line: ``kind: [POST] URL [| format arguments]``.

    kev:  ``| json <path>`` (CVE ids at that path), ``| csv <column>`` or ``| text`` (every CVE-id in the response, the
          default: survives most format changes)
    epss: ``| json <rows path> <cve field> <score field> [<percentile field>]`` or ``| csv <cve column> <score column>
          [<percentile column>]``; a URL with {cves} is asked for 100 CVEs at a time, one without downloads everything
    cvss: URL with {cve}; ``| json <path>, <path>, ...`` - the highest number found at these paths is the score
    osv:  URL of an OSV-compatible query API (POST {"package": ..., "version": ...})
    ``kind: off`` uses nothing for that kind. Empty lines and # comments are skipped; a wrong line raises ValueError."""
    out: dict[str, list[Source]] = defaultdict(list)
    off: set[str] = set()
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, sep, rest = line.partition(":")
        kind, rest = kind.strip().lower(), rest.strip()
        if not sep or kind not in SOURCE_KINDS:
            raise ValueError(f"line {n}: start with the kind and a colon ({', '.join(SOURCE_KINDS)}), e.g. kev: https://...")
        if rest.lower() == "off":
            off.add(kind)
            continue
        target, _, fmt = rest.partition(" | ")
        target = target.strip()
        method = "GET"
        if target[:5].upper() == "POST ":
            method, target = "POST", target[5:].strip()
        if not target.startswith(("http://", "https://")) or " " in target:
            raise ValueError(f"line {n}: '{target}' is not an http:// or https:// address")
        src = Source(kind, target, method, line=n)
        fmt = fmt.strip()
        if kind == "osv":
            src.method = "POST"
        elif fmt:
            ftype, _, fargs = fmt.partition(" ")
            src.fmt = ftype.lower()
            if src.fmt not in FORMATS:
                raise ValueError(f"line {n}: unknown format '{ftype}' - use json, csv or text")
            if kind == "cvss":
                src.args = [a.strip() for a in fargs.split(",") if a.strip()]
            else:
                src.args = fargs.split()
            need = {"kev": {"json": 1, "csv": 1, "text": 0}, "epss": {"json": 3, "csv": 2, "text": 99},
                    "cvss": {"json": 1, "csv": 99, "text": 99}}[kind][src.fmt]
            if need == 99:
                raise ValueError(f"line {n}: {kind} sources can't use the {src.fmt} format")
            if len(src.args) < need:
                raise ValueError(f"line {n}: {kind} with {src.fmt} needs {need} argument(s) - see the help text")
        if kind == "cvss" and "{cve}" not in target:
            raise ValueError(f"line {n}: a cvss address needs {{cve}} where the CVE id goes")
        out[kind].append(src)
    return {k: [] if k in off else out.get(k, []) for k in SOURCE_KINDS}


def sources(settings: Settings) -> tuple[dict[str, list[Source]], str | None]:
    """The sources to use: yours, or the built-in list when the field is empty; (sources, error of your list)."""
    text = settings.vuln_sources if (settings.vuln_sources or "").strip() else Settings.model_fields["vuln_sources"].default
    try:
        return parse_sources(text), None
    except ValueError as exc:  # saved before validation existed / edited in the database: built-in list
        return parse_sources(Settings.model_fields["vuln_sources"].default), str(exc)


def extract_kev(src: Source, body: bytes) -> set[str]:
    text = decode(body)
    if src.fmt == "json":
        vals = [str(v) for a in src.args[:1] for v in jpath(json.loads(text), a)]
        ids = {v.upper() for v in vals if CVE_RE.fullmatch(v.strip())}
    elif src.fmt == "csv":
        ids = {r.get(src.args[0], "").strip().upper() for r in csv_rows(text)}
        ids = {i for i in ids if CVE_RE.fullmatch(i)}
    else:
        ids = {m.upper() for m in CVE_RE.findall(text)}
    return ids


def extract_epss(src: Source, body: bytes) -> dict[str, tuple[float, float | None]]:
    text = decode(body)
    out: dict[str, tuple[float, float | None]] = {}
    if src.fmt in ("", "json"):
        rows_path, cve_f, score_f, pct_f = (src.args + [None] * 4)[:4] if src.args else ("data[]", "cve", "epss", "percentile")
        rows = [(r.get(cve_f), r.get(score_f), r.get(pct_f) if pct_f else None)
                for r in jpath(json.loads(text), rows_path) if isinstance(r, dict)]
    else:
        cve_f, score_f, pct_f = (src.args + [None] * 3)[:3]
        rows = [(r.get(cve_f), r.get(score_f), r.get(pct_f) if pct_f else None) for r in csv_rows(text)]
    for cve, score, pct in rows:
        s = number(score)
        if cve and s is not None and CVE_RE.fullmatch(str(cve).strip()):
            out[str(cve).strip().upper()] = (s, number(pct))
    return out


def extract_cvss(src: Source, body: bytes) -> float | None:
    data = json.loads(decode(body))
    scores = [s for p in (src.args or ["vulnerabilities[].cve.metrics.*[].cvssData.baseScore"])
              for s in (number(v) for v in jpath(data, p)) if s is not None and 0 <= s <= 10]
    return max(scores) if scores else None


# -------------------------------------------------------------------- CVSS ---
_V3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
       "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
       "A": {"H": 0.56, "L": 0.22, "N": 0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score of a CVSS 3.x vector (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8); None if it is not one."""
    if not (vector or "").startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _V3["C"][m["C"]]) * (1 - _V3["I"][m["I"]]) * (1 - _V3["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _V3["AV"][m["AV"]] * _V3["AC"][m["AC"]] * pr * _V3["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


# ------------------------------------------------------------------ images ---
DOCKER_HUB = ("docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com")


@dataclass(frozen=True)
class ImageName:
    registry: str
    repo: str
    tag: str | None
    digest: str | None

    @property
    def full(self) -> str:
        return f"{self.registry}/{self.repo}"

    def names(self) -> list[str]:
        """Ways to write this image, for name patterns (nextcloud*, */nextcloud*, lscr.io/linuxserver/*)."""
        short = self.repo[8:] if self.registry == "docker.io" and self.repo.startswith("library/") else self.repo
        out = [self.full, short, self.repo]
        if self.tag:
            out += [f"{self.full}:{self.tag}", f"{short}:{self.tag}"]
        return list(dict.fromkeys(out))


def parse_image(image: str) -> ImageName:
    ref = (image or "").strip()
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    if ref.rfind(":") > ref.rfind("/"):
        ref, tag = ref.rsplit(":", 1)
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first.lower(), ref.split("/", 1)[1]
    else:
        registry, repo = "docker.io", ref
    if registry in DOCKER_HUB:
        registry = "docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return ImageName(registry, repo.lower(), tag or (None if digest else "latest"), digest)


def matches(patterns: list[str], names: list[str]) -> bool:
    return any(fnmatch.fnmatch(n.lower(), p.lower()) for p in patterns for n in names)


def patterns(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\n]+", text or "") if p.strip()]


# ------------------------------------------------------------ ignore rules ---
@dataclass
class IgnoreRule:
    what: str           # CVE / GHSA id, pkg:<name>, or a pattern (CVE-2023-*)
    where: list[str]    # container / image name patterns; empty = everywhere
    until: date | None
    text: str

    def applies(self, f: dict[str, Any], names: list[str], today: date) -> bool:
        if self.until and today > self.until:
            return False
        if self.where and not matches(self.where, names):
            return False
        w = self.what.lower()
        if w.startswith("pkg:"):  # the package or its source package (pkg:dotnet10 covers dotnet-host-10.0, ...)
            return any(fnmatch.fnmatch(str(f.get(k) or "").lower(), w[4:]) for k in ("package", "upstream"))
        ids = [str(f.get("vuln", ""))] + list(f.get("aliases") or [])
        return any(fnmatch.fnmatch(i.lower(), w) for i in ids)


def parse_ignore(text: str) -> list[IgnoreRule]:
    """One per line: ``<CVE / GHSA id, pkg:<package> or pattern> [on <containers / images>] [until YYYY-MM-DD]``."""
    out = []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"(\S+)(?:\s+on\s+(.+?))?(?:\s+until\s+(\S+))?", line, re.I)
        if not m:
            raise ValueError(f"line {n}: use 'CVE-2024-1234 [on nextcloud*] [until 2026-12-31]'")
        until = None
        if m.group(3):
            try:
                until = date.fromisoformat(m.group(3))
            except ValueError as exc:
                raise ValueError(f"line {n}: '{m.group(3)}' is not a date like 2026-12-31") from exc
        out.append(IgnoreRule(m.group(1), patterns(m.group(2) or ""), until, line))
    return out


# -------------------------------------------------------------- app checks ---
VERSION_FROM = ("env", "label", "tag", "package")
DEFAULT_VERSION_RE = r"(\d+(?:\.\d+)+)"


@dataclass
class AppCheck:
    images: list[str]
    source: str           # env | label | tag | package
    name: str             # variable / label / package name ('' for tag)
    regex: str
    ecosystem: str
    package: str
    line: int
    text: str

    def version(self, info: dict[str, Any]) -> tuple[str | None, str]:
        """(version, where it came from) out of the image's labels / environment / tag / SBOM packages."""
        if self.source == "env":
            raw, where = (info.get("env") or {}).get(self.name), f"environment variable {self.name}"
        elif self.source == "label":
            raw, where = (info.get("labels") or {}).get(self.name), f"image label {self.name}"
        elif self.source == "tag":
            raw, where = info.get("tag"), "image tag"
        else:
            raw = next((p["version"] for p in info.get("packages") or [] if p.get("name") == self.name), None)
            where = f"package {self.name}"
        if not raw:
            return None, where
        m = re.search(self.regex, str(raw))
        return (m.group(1) if m and m.groups() else m.group(0) if m else None), where


def parse_app_checks(text: str) -> list[AppCheck]:
    """One per line: ``<image patterns> | <env|label|tag|package> [name] [/regex/] | <OSV ecosystem> <package>``."""
    out = []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 3:
            raise ValueError(f"line {n}: three parts separated by ' | ': images | version source | ecosystem package")
        imgs = patterns(parts[0])
        src = parts[1]
        rx = DEFAULT_VERSION_RE
        if m := re.search(r"\s/(.+)/$", " " + src):
            rx, src = m.group(1), src[: len(src) - len(m.group(0)) + 1].strip()
            try:
                re.compile(rx)
            except re.error as exc:
                raise ValueError(f"line {n}: the /regex/ is not valid ({exc})") from exc
        kind, _, name = src.partition(" ")
        kind, name = kind.lower(), name.strip()
        if kind not in VERSION_FROM:
            raise ValueError(f"line {n}: the version comes from env, label, tag or package - not '{kind}'")
        if kind != "tag" and not name:
            raise ValueError(f"line {n}: {kind} needs a name (e.g. env NEXTCLOUD_VERSION)")
        eco, _, pkg = parts[2].partition(" ")
        if not imgs or not eco or not pkg.strip():
            raise ValueError(f"line {n}: give image patterns and '<ecosystem> <package>', e.g. Packagist nextcloud/server")
        out.append(AppCheck(imgs, kind, name, rx, eco, pkg.strip(), n, line))
    return out


@dataclass
class VersionSource:
    source: str   # label | env | tag | package
    name: str     # may contain {NAME} (image name for env: NEXTCLOUD) or {name} (nextcloud)
    regex: str
    text: str


def parse_version_sources(text: str) -> list[VersionSource]:
    """Where to read the version of every image, tried top to bottom: ``label NAME``, ``env NAME``, ``tag`` or
    ``package NAME``, optionally followed by a /regex/ (first group = the version). {NAME} / {name} stand for the
    image's own name (FILEFLOWS / fileflows for revenz/fileflows)."""
    out = []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rx = DEFAULT_VERSION_RE
        if m := re.search(r"\s/(.+)/$", " " + line):
            rx, line = m.group(1), line[: len(line) - len(m.group(0)) + 1].strip()
            try:
                re.compile(rx)
            except re.error as exc:
                raise ValueError(f"line {n}: the /regex/ is not valid ({exc})") from exc
        kind, _, name = line.partition(" ")
        kind, name = kind.lower(), name.strip()
        if kind not in VERSION_FROM:
            raise ValueError(f"line {n}: use label NAME, env NAME, tag or package NAME - not '{kind}'")
        if kind != "tag" and not name:
            raise ValueError(f"line {n}: {kind} needs a name")
        out.append(VersionSource(kind, name, rx, raw.strip()))
    return out


def detect_version(data: dict[str, Any], image: ImageName, rules: list[VersionSource]) -> dict[str, Any]:
    """The version of the software in an image: {version, raw, from} from the first rule that gives one, else
    {version: None, tried: [...]}. Only shown (and used for the alert text); CVEs of the app itself need an app check."""
    base = image.repo.rsplit("/", 1)[-1]
    names = {"{NAME}": re.sub(r"[^A-Za-z0-9]+", "_", base).upper(), "{name}": base.lower()}
    tried = []
    for r in rules:
        name = r.name
        for k, v in names.items():
            name = name.replace(k, v)
        chk = AppCheck([], r.source, name, r.regex, "", "", 0, r.text)
        version, where = chk.version(data)
        if version and r.source == "label" and version == data.get("os_version"):
            tried.append(f"{where} (= the base image's OS release {version}, skipped)")
            continue  # inherited from the base image: ubuntu:26.04 labels itself 26.04
        tried.append(where)
        if version:
            raw = {"env": (data.get("env") or {}).get(name), "label": (data.get("labels") or {}).get(name),
                   "tag": data.get("tag")}.get(r.source) or version
            return {"version": version, "raw": str(raw)[:120], "from": where}
    return {"version": None, "tried": tried}


def parse_env(text: str) -> dict[str, str]:
    out = {}
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, v = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k.strip()):
            raise ValueError(f"line {n}: use NAME=value")
        out[k.strip()] = v.strip()
    return out


def parse_threshold(value: Any, label: str, top: float) -> float | None:
    v = str(value or "").strip()
    if not v:
        return None
    f = number(v)
    if f is None or not 0 <= f <= top:
        raise ValueError(f"{label}: a number from 0 to {top:g}")
    return f


# ---------------------------------------------------------------- findings ---
def _cvss_entries(v: dict[str, Any]) -> list[tuple[float, str, str]]:
    out = []
    for c in v.get("cvss") or []:
        score = number((c.get("metrics") or {}).get("baseScore"))
        if score is None:
            score = cvss3_score(c.get("vector") or "")
        if score is not None and str(c.get("version", "3")).split(".")[0] in ("3", "4"):
            out.append((score, str(c.get("source") or v.get("namespace") or ""), str(c.get("version") or "")))
    return out


def parse_grype(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Grype JSON (-o json) -> one finding per vulnerability + package + version; unknown fields are ignored."""
    found: dict[tuple[str, str, str], dict[str, Any]] = {}
    for m in doc.get("matches") or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vid = str(v.get("id") or "")
        if not vid:
            continue
        ids = [vid] + [str(r.get("id")) for r in related if r.get("id")]
        cves = [i.upper() for i in ids if CVE_RE.fullmatch(i)]
        scores = _cvss_entries(v) + [e for r in related for e in _cvss_entries(r)]
        nvd = [s for s in scores if "nvd" in s[1].lower()]
        best = max(nvd or scores, default=None, key=lambda s: s[0])
        epss = [(number(e.get("epss")), number(e.get("percentile"))) for x in [v, *related] for e in x.get("epss") or []]
        epss = [e for e in epss if e[0] is not None]
        kev = bool(v.get("knownExploited") or any(r.get("knownExploited") for r in related))
        fix = v.get("fix") or {}
        # the package database entry (evidence: primary) first, not a copyright file that also belongs to it
        locs = [loc.get("path") for loc in sorted(art.get("locations") or [], key=lambda x: (
            (x.get("annotations") or {}).get("evidence") != "primary", x.get("path") or "")) if loc.get("path")]
        key = (vid, str(art.get("name") or "?"), str(art.get("version") or ""))
        up = next((u for u in art.get("upstreams") or [] if u.get("name")), {})
        f = found.get(key)
        if f is None:
            f = found[key] = {
                "vuln": vid, "package": key[1], "version": key[2], "pkg_type": art.get("type") or "",
                "aliases": sorted(set(ids) - {vid}), "cves": sorted(set(cves)),
                "severity": str(v.get("severity") or "Unknown"),
                "cvss": best[0] if best else None, "cvss_source": f"{best[1] or 'grype'} {best[2]}".strip() if best else None,
                "kev": kev, "epss": max(e[0] for e in epss) if epss else None,
                "epss_pct": max((e[1] for e in epss if e[1] is not None), default=None),
                "fix_versions": list(fix.get("versions") or []), "fix_state": fix.get("state") or "unknown",
                # the advisory the fixed version comes from (the distribution's tracker), else the first link
                "url": v.get("dataSource") or (v.get("urls") or [None])[0],
                "upstream": str(up.get("name") or ""), "matched": match_info(m),
                "description": (v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
                                or "")[:600],
                "locations": [], "source": "grype", "purl": art.get("purl") or "",
            }
        f["locations"] = list(dict.fromkeys(f["locations"] + locs))[:10]
    for f in found.values():
        if note := version_note(f):
            f["matched"] = {**f["matched"], "note": note["text"], "probably_fixed": note["fixed"]}
    return list(found.values())


def _dpkg_order(c: str) -> int:
    return -1 if c == "~" else ord(c) if c.isalpha() else ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += i < len(a) and not a[i].isdigit()
            j += j < len(b) and not b[j].isdigit()
        da = re.match(r"\d*", a[i:]).group(0)
        db_ = re.match(r"\d*", b[j:]).group(0)
        i, j = i + len(da), j + len(db_)
        if int(da or 0) != int(db_ or 0):
            return -1 if int(da or 0) < int(db_ or 0) else 1
    return 0


def dpkg_compare(a: str, b: str) -> int:
    """Debian version order (epoch:upstream-revision, ~ sorts before everything): -1, 0 or 1."""
    def split(v: str) -> tuple[int, str, str]:
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch) if epoch.isdigit() else 0, up, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def version_note(f: dict[str, Any]) -> dict[str, Any] | None:
    """Ubuntu / Debian fixes are filed under the SOURCE package's version, e.g. dotnet10 10.0.114-10.0.14-0ubuntu1~26.04.1
    (SDK 10.0.114, runtime 10.0.14), while its binary packages carry their own: dotnet-host-10.0 10.0.14-0ubuntu1~26.04.1.
    When Grype only knew the binary version it compares the two formats (10.0.14 < 10.0.114) and flags a package that
    is fixed. Then the fix's own part for this binary is compared instead: {"fixed": bool, "text": ...}."""
    if f.get("pkg_type") != "deb" or not f.get("fix_versions"):
        return None
    m = f.get("matched") or {}
    searched = (m.get("searched") or "").rpartition(" ")[2]
    inst = str(f.get("version") or "")
    if searched and searched != inst:
        return None  # Grype compared the source package's own version: formats match
    for fix in f["fix_versions"]:
        up = fix.split(":", 1)[-1]
        if up.count("-") >= 2 and inst.split(":", 1)[-1].count("-") == 1:
            embedded = up.split("-", 1)[1]
            if inst.split("-", 1)[0].split(":")[-1].split(".")[0] != embedded.split(".")[0]:
                continue  # not the same version line: no conclusion
            done = dpkg_compare(inst, embedded) >= 0
            return {"fixed": done, "embedded": embedded,
                    "text": (f"{inst} is the binary package's version; the fix {fix} is the source package's (its "
                             f"binary packages get {embedded}). " + (f"{inst} ≥ {embedded}: already fixed - Grype "
                             "compared different version formats." if done else f"{inst} < {embedded}: not fixed yet."))}
    return None


def match_info(m: dict[str, Any]) -> dict[str, Any]:
    """How Grype matched: which package name / version it looked up, in which advisory data, against which range -
    so a finding can be checked by hand (e.g. Ubuntu files fixes under the SOURCE package: dotnet10 for
    dotnet-host-10.0, with the source package's version)."""
    d = next(iter(m.get("matchDetails") or []), None) or {}
    by, found = d.get("searchedBy") or {}, d.get("found") or {}
    pkg = by.get("package") or {}
    distro = by.get("distro") or {}
    out = {"type": d.get("type") or "", "matcher": d.get("matcher") or "",
           "searched": " ".join(x for x in (pkg.get("name"), pkg.get("version")) if x),
           "constraint": found.get("versionConstraint") or "",
           "namespace": by.get("namespace") or "",
           "distro": " ".join(x for x in (distro.get("type"), distro.get("version")) if x)}
    if by.get("cpes"):
        out["cpes"] = list(by["cpes"])[:3]
    return {k: v for k, v in out.items() if v}


def group_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per image + vulnerability + source package + fix: a CVE in one Ubuntu / Debian source package (dotnet10)
    is reported by Grype once for every binary package built from it (dotnet-host-10.0, aspnetcore-runtime-10.0, ...)."""
    out: dict[tuple, dict[str, Any]] = {}
    for r in rows:
        grp = r.get("upstream") or r["package"]
        key = (r.get("image_key"), r["vuln"], grp, tuple(r.get("fix_versions") or []))
        g = out.get(key)
        pkg = {"name": r["package"], "version": r["version"], "locations": list(r.get("locations") or [])[:3],
               "fixed": bool((r.get("matched") or {}).get("probably_fixed"))}
        if g is None:
            g = out[key] = {**r, "packages": [pkg], "group": grp}
        elif g["packages"][0]["fixed"] and not pkg["fixed"]:  # the row shows a package that still needs the fix
            g.update({k: v for k, v in r.items() if k not in ("packages", "group")})
            g["packages"].append(pkg)
        else:
            g["packages"].append(pkg)
            for k in ("kev", "alerted"):
                g[k] = bool(g.get(k) or r.get(k))
            for k in ("cvss", "epss", "epss_pct"):
                if r.get(k) is not None and (g.get(k) is None or r[k] > g[k]):
                    g[k] = r[k]
            if g.get("ignored") and not r.get("ignored"):
                g["ignored"], g["why"] = None, r.get("why")
    for g in out.values():
        g["packages"].sort(key=lambda p: p["name"])
    return list(out.values())


def osv_findings(doc: dict[str, Any], check: AppCheck, version: str) -> list[dict[str, Any]]:
    """OSV query result -> findings for the app itself."""
    out = []
    for v in doc.get("vulns") or []:
        vid = str(v.get("id") or "")
        if not vid:
            continue
        aliases = [str(a) for a in v.get("aliases") or []]
        cves = sorted({a.upper() for a in [vid, *aliases] if CVE_RE.fullmatch(a)})
        score = max((s for s in (cvss3_score(x.get("score") or "") for x in v.get("severity") or []) if s is not None),
                    default=None)
        sev = str((v.get("database_specific") or {}).get("severity") or "")
        fixed = sorted({e["fixed"] for a in v.get("affected") or [] for r in a.get("ranges") or []
                        for e in r.get("events") or [] if e.get("fixed")})
        out.append({"vuln": cves[0] if len(cves) == 1 else vid, "package": check.package, "version": version,
                    "pkg_type": f"{check.ecosystem} (app check)",
                    "aliases": sorted(set([vid, *aliases]) - {cves[0] if len(cves) == 1 else vid}), "cves": cves,
                    "severity": sev.title() or "Unknown", "cvss": score,
                    "cvss_source": "OSV CVSS 3" if score is not None else None, "kev": False, "epss": None,
                    "epss_pct": None, "fix_versions": fixed, "fix_state": "fixed" if fixed else "unknown",
                    "url": next((r.get("url") for r in v.get("references") or [] if r.get("type") == "ADVISORY"),
                                f"https://osv.dev/vulnerability/{vid}"),
                    "description": str(v.get("summary") or v.get("details") or "")[:600], "locations": [],
                    "source": f"app check (line {check.line})", "purl": "", "upstream": "",
                    "matched": {"type": "app check", "searched": f"{check.ecosystem} {check.package} {version}",
                                "constraint": "affected per OSV" + (f", fixed in {', '.join(fixed[:3])}" if fixed else "")}})
    return out


def score_of(f: dict[str, Any]) -> float | None:
    """CVSS, or an estimate from the severity word when no score is known (marked as such on the page)."""
    if f.get("cvss") is not None:
        return float(f["cvss"])
    return SEVERITY_SCORE.get(str(f.get("severity") or "").lower())


@dataclass
class Policy:
    min_cvss: float
    kev_always: bool
    epss_min: float | None
    only_fixed: bool
    ignore: list[IgnoreRule]

    @classmethod
    def of(cls, s: Settings) -> "Policy":
        try:
            ignore = parse_ignore(s.vuln_ignore)
        except ValueError:
            ignore = []
        return cls(parse_threshold(s.vuln_min_cvss, "", 10) or 0.0, s.vuln_kev_always,
                   parse_threshold(s.vuln_epss_min, "", 1), s.vuln_only_fixed, ignore)

    def judge(self, f: dict[str, Any], names: list[str], today: date | None = None) -> tuple[bool, str | None, str]:
        """(alert?, ignore rule that matched, why) for one finding."""
        for r in self.ignore:
            if r.applies(f, names, today or date.today()):
                return False, r.text, "ignored"
        s = score_of(f)
        if (f.get("matched") or {}).get("probably_fixed"):
            return False, None, "already fixed (Grype compared a binary version with the source package's)"
        if f.get("kev") and self.kev_always:
            return True, None, "actively exploited (CISA KEV)"
        fixed = f.get("fix_state") == "fixed" or bool(f.get("fix_versions"))
        if self.only_fixed and not fixed:
            return False, None, "no fixed version yet"
        if s is not None and s >= self.min_cvss:
            return True, None, f"CVSS {s:.1f} ≥ {self.min_cvss:g}"
        if self.epss_min is not None and (f.get("epss") or 0) >= self.epss_min:
            return True, None, f"EPSS {f['epss']:.0%} ≥ {self.epss_min:.0%}"
        return False, None, "below the threshold"


def level_of(f: dict[str, Any]) -> str:
    if f.get("kev"):
        return "critical"
    s = score_of(f) or 0
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


# -------------------------------------------------------------------- tools ---
class ToolError(RuntimeError):
    pass


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


async def run_tool(args: list[str], env: dict[str, str], timeout: float, check: bool = True) -> bytes:
    """Run Grype / Syft; stdout, or ToolError with what went wrong (missing, timeout, its own error lines)."""
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                    stdin=asyncio.subprocess.DEVNULL, env=env)
    except FileNotFoundError as exc:
        raise ToolError(f"'{args[0]}' was not found - the Looking Glass image includes it; running from source, install "
                        f"it or set its path under Settings › Container vulnerabilities") from exc
    except PermissionError as exc:
        raise ToolError(f"'{args[0]}' can't be run (permission denied)") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ToolError(f"{Path(args[0]).name} did not finish within {timeout / 60:.0f} minutes (Settings › Container "
                        f"vulnerabilities › Time limit)") from exc
    if proc.returncode != 0 and (check or not out.strip()):
        lines = [ln.strip() for ln in _ANSI.sub("", err.decode("utf-8", "replace")).splitlines() if ln.strip()]
        useful = [ln for ln in lines if re.search(r"error|fail|denied|unauthor|not found|no such|refused|timeout|manifest", ln, re.I)]
        raise ToolError(f"{Path(args[0]).name} exit {proc.returncode}: " + (" · ".join((useful or lines)[-3:]) or "no output")[:700])
    return out


# --------------------------------------------------------------- scheduler ---
@dataclass
class Target:
    key: str                     # digest, or image name when the digest is unknown
    image: str                   # as the containers use it
    name: ImageName
    digest: str | None = None
    image_id: str | None = None
    docker_url: str | None = None
    containers: list[dict[str, Any]] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    local_only: bool = False     # built locally / no registry digest: only the Docker API can export it

    def names(self) -> list[str]:
        return self.name.names() + [c["name"] for c in self.containers]


def safe_name(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:32]


class VulnScanner:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.status: dict[str, Any] = {}
        self.wake = asyncio.Event()
        self.base = Path(settings.data_dir) / "vulnscan"

    # ------------------------------------------------------------ status ---
    async def load_status(self) -> None:
        self.status = await db.kv_get("vulnscan:status", {}) or {}

    async def save_status(self, **kw: Any) -> None:
        self.status.update(kw)
        await db.kv_set("vulnscan:status", self.status)

    async def problem(self, area: str, ok: bool, title: str = "", text: str = "", severity: str = "medium") -> None:
        """A problem that leaves you (partly) blind: an alert of its own, closed by itself once it works again."""
        fp = f"vulnscan:{area}"
        if ok:
            await close_alerts(PROBLEM_RULE, [fp], "it works again")
            return
        await raise_alert(PROBLEM_RULE, severity, title, fp, text + "\n\nDetails and every source's last answer: "
                          "Looking Glass › Vulnerabilities. Settings: Settings › Container vulnerabilities.",
                          data={"area": area}, mode="max")

    # --------------------------------------------------------- environment ---
    def tool_env(self) -> dict[str, str]:
        s = self.s
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY",
                                                             "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                                                             "SSL_CERT_FILE", "SSL_CERT_DIR")}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.setdefault("HOME", str(self.base))
        env.update({"GRYPE_DB_CACHE_DIR": str(self.base / "grype-db"), "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false", "SYFT_CHECK_FOR_APP_UPDATE": "false",
                    "XDG_CACHE_HOME": str(self.base / "cache")})
        if s.vuln_grype_db_url.strip():
            env["GRYPE_DB_UPDATE_URL"] = s.vuln_grype_db_url.strip()
        if s.vuln_registry_user.strip() and s.vuln_registry_password:
            host = (s.vuln_registry_host or "docker.io").strip()
            for tool in ("SYFT", "GRYPE"):
                env[f"{tool}_REGISTRY_AUTH_AUTHORITY"] = "index.docker.io" if host in DOCKER_HUB else host
                env[f"{tool}_REGISTRY_AUTH_USERNAME"] = s.vuln_registry_user.strip()
                env[f"{tool}_REGISTRY_AUTH_PASSWORD"] = s.vuln_registry_password
        try:
            env.update(parse_env(s.vuln_tool_env))
        except ValueError:
            pass
        return env

    def timeout(self) -> float:
        return max(2, self.s.vuln_scan_timeout) * 60.0

    async def tools(self) -> bool:
        """Grype and Syft versions; False (with the reason on the page and an alert) when one can't run."""
        env, st = self.tool_env(), {}
        for name, path in (("grype", self.s.vuln_grype_path or "grype"), ("syft", self.s.vuln_syft_path or "syft")):
            try:
                out = await run_tool([path, "version", "-o", "json"], env, 60)
                try:
                    ver = json.loads(out).get("version")
                except ValueError:
                    ver = (re.search(rb"Version:\s*(\S+)", out) or [b"", b"?"])[1].decode()
                st[name] = {"ok": True, "version": ver, "path": path}
            except ToolError as exc:
                st[name] = {"ok": False, "error": str(exc), "path": path}
        await self.save_status(tools=st)
        bad = [f"{k}: {v['error']}" for k, v in st.items() if not v["ok"]]
        await self.problem("tools", not bad, "Vulnerability scanner can't run", "Container images are not being "
                           "checked for vulnerabilities: " + "; ".join(bad))
        return not bad

    async def update_db(self) -> None:
        """grype db update + status. A failed update keeps the old database while Grype still accepts it (it refuses
        one older than 5 days by default); both are reported."""
        env, path = self.tool_env(), self.s.vuln_grype_path or "grype"
        (self.base / "grype-db").mkdir(parents=True, exist_ok=True)
        st = dict(self.status.get("db") or {})
        st["tried"] = time.time()
        try:
            await run_tool([path, "db", "update"], env, self.timeout())
            st.update(update_ok=True, update_error=None, updated=time.time())
        except ToolError as exc:
            st.update(update_ok=False, update_error=str(exc))
            log.warning("vulnerability database update failed: %s", exc)
        try:
            # exits 1 without a (valid) database, but still says why in its JSON
            info = json.loads(await run_tool([path, "db", "status", "-o", "json"], env, 120, check=False))
            st.update(built=info.get("built"), schema=info.get("schemaVersion"), valid=info.get("valid", True),
                      status_error=info.get("error") or None, source=info.get("from"))
        except (ToolError, ValueError) as exc:
            st.update(valid=False, status_error=str(exc))
        age = None
        if st.get("built"):
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(st["built"]).replace("Z", "+00:00"))).total_seconds()
            except ValueError:
                pass
        st["age_days"] = round(age / 86400, 1) if age is not None else None
        await self.save_status(db=st)
        stale = age is None or age > 3 * 86400
        ok = bool(st.get("valid")) and not stale
        why = st.get("update_error") or st.get("status_error") or "no database yet"
        await self.problem("db", ok, "Vulnerability database outdated", (
            f"Grype's vulnerability database is {st['age_days']} days old" if age is not None else
            "Grype has no usable vulnerability database") + f" - new CVEs are missed. Last update: {why}. The container "
            "needs HTTPS access to the database address (Settings › Container vulnerabilities › Grype database "
            "address; empty = Grype's own).")

    # --------------------------------------------------------------- sources ---
    async def fetch(self, client: httpx.AsyncClient, src: Source, url: str, body: Any = None) -> bytes:
        h = {}
        if self.s.vuln_nvd_api_key and (httpx.URL(url).host or "").endswith("nvd.nist.gov"):
            h["apiKey"] = self.s.vuln_nvd_api_key  # only ever sent to NVD
        r = await (client.post(url, json=body, headers=h) if src.method == "POST" else client.get(url, headers=h))
        if r.status_code in (403, 429) and "nvd.nist.gov" in url:
            raise RuntimeError(f"HTTP {r.status_code}: NVD limits requests - an NVD API key (free) raises the limit")
        r.raise_for_status()
        return r.content

    async def source_status(self, kind: str, ok: bool, **kw: Any) -> None:
        st = dict(self.status.get("sources") or {})
        cur = dict(st.get(kind) or {})
        now = time.time()
        if ok:
            cur.update(ok=True, error=None, updated=now, failing_since=None, **kw)
        else:
            cur.update(ok=False, tried=now, failing_since=cur.get("failing_since") or now, **kw)
        st[kind] = cur
        await self.save_status(sources=st)
        failing = not ok and now - cur["failing_since"] > SOURCE_GRACE[kind]
        await self.problem(f"source:{kind}", not failing, f"Vulnerability source failing: {kind}",
                           f"No answer from any {kind} source ({SOURCE_KINDS[kind]}) since "
                           f"{datetime.fromtimestamp(cur.get('failing_since') or now, timezone.utc):%Y-%m-%d %H:%M} UTC: "
                           f"{cur.get('error')}. Findings are still made, but without this information. Change or add "
                           "an address under Settings › Container vulnerabilities › Sources.", severity="low")

    async def refresh_kev(self, client: httpx.AsyncClient, srcs: list[Source], force: bool = False) -> None:
        st = (self.status.get("sources") or {}).get("kev") or {}
        if not srcs:
            await self.save_status(sources={**(self.status.get("sources") or {}), "kev": {"off": True}})
            await self.problem("source:kev", True)
            return
        if not force and st.get("ok") and time.time() - (st.get("updated") or 0) < KEV_HOURS * 3600:
            return
        errors = []
        for src in srcs:
            try:
                ids = extract_kev(src, await self.fetch(client, src, src.url))
                if len(ids) < 10:
                    raise RuntimeError(f"only {len(ids)} CVE ids in the answer - wrong format or path?")
                await db.kv_set("vulnscan:kev", sorted(ids))
                await self.source_status("kev", True, count=len(ids), url=src.url)
                return
            except Exception as exc:  # noqa: BLE001 - the next source may work
                errors.append(f"line {src.line} {src.label()}: {_err(exc)}")
        await self.source_status("kev", False, error="; ".join(errors)[:900])

    async def enrich_epss(self, client: httpx.AsyncClient, srcs: list[Source], cves: set[str]) -> None:
        """EPSS for these CVEs into vuln_cache (kept a day)."""
        if not srcs:
            return
        fresh = {r["id"] for r in await db.pool().fetch(
            "SELECT id FROM vuln_cache WHERE kind = 'epss' AND id = ANY($1::text[]) AND fetched > now() - make_interval(hours => $2)",
            list(cves), EPSS_HOURS)}
        todo = sorted(cves - fresh)
        if not todo:
            return
        errors: list[str] = []
        for src in srcs:
            try:
                got: dict[str, tuple[float, float | None]] = {}
                if "{cves}" in src.url:
                    for i in range(0, len(todo), 100):
                        chunk = todo[i:i + 100]
                        got.update(extract_epss(src, await self.fetch(client, src, src.url.replace("{cves}", ",".join(chunk)))))
                else:
                    allscores = extract_epss(src, await self.fetch(client, src, src.url))
                    if len(allscores) < 1000:
                        raise RuntimeError(f"only {len(allscores)} scores in the download - wrong format or columns?")
                    got = {c: allscores[c] for c in todo if c in allscores}
                rows = [("epss", c, {"epss": got[c][0], "pct": got[c][1]} if c in got else {"none": True}) for c in todo]
                await db.pool().executemany(
                    "INSERT INTO vuln_cache (kind, id, value, fetched) VALUES ($1, $2, $3, now()) "
                    "ON CONFLICT (kind, id) DO UPDATE SET value = EXCLUDED.value, fetched = now()", rows)
                await self.source_status("epss", True, count=len(got), url=src.url)
                return
            except Exception as exc:  # noqa: BLE001
                errors.append(f"line {src.line} {src.label()}: {_err(exc)}")
        await self.source_status("epss", False, error="; ".join(errors)[:900])

    async def enrich_cvss(self, client: httpx.AsyncClient, srcs: list[Source], cves: set[str]) -> None:
        """Scores for CVEs Grype / OSV gave none (rate limited: NVD allows 5 requests in 30 s without a key)."""
        if not srcs or not cves:
            return
        known = {r["id"] for r in await db.pool().fetch(
            "SELECT id FROM vuln_cache WHERE kind = 'cvss' AND id = ANY($1::text[]) AND fetched > now() - make_interval(days => $2)",
            list(cves), CVSS_DAYS)}
        todo = sorted(cves - known)[:CVSS_LOOKUPS_PER_RUN]
        if not todo:
            return
        pause = 1.0 if self.s.vuln_nvd_api_key else 6.5
        done, errors = 0, []
        for cve in todo:
            last = None
            for src in srcs:
                try:
                    score = extract_cvss(src, await self.fetch(client, src, src.url.replace("{cve}", cve)))
                    await db.pool().execute(
                        "INSERT INTO vuln_cache (kind, id, value, fetched) VALUES ('cvss', $1, $2, now()) "
                        "ON CONFLICT (kind, id) DO UPDATE SET value = EXCLUDED.value, fetched = now()",
                        cve, {"cvss": score, "src": src.label()} if score is not None else {"none": True})
                    done += 1
                    last = None
                    break
                except Exception as exc:  # noqa: BLE001
                    last = f"line {src.line} {src.label()}: {_err(exc)}"
                    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404:
                        continue
            if last:
                errors.append(f"{cve}: {last}")
                if len(errors) >= 3 and not done:
                    break  # every source down: stop early, try again next run
            await asyncio.sleep(pause)
        if errors and not done:
            await self.source_status("cvss", False, error="; ".join(errors)[:900])
        else:
            await self.source_status("cvss", True, count=done, url=srcs[0].url,
                                     note=f"{len(errors)} lookup(s) failed" if errors else None)

    # ------------------------------------------------------------- inventory ---
    async def inventory(self) -> list[Target]:
        """Images to scan: Unraid containers (+ their digests from the Docker API) and the extra images you listed."""
        targets: dict[str, Target] = {}
        inv: dict[str, Any] = {}
        excl = patterns(self.s.vuln_exclude)
        servers = await db.pool().fetch("SELECT id, name, docker_url FROM unraid_servers WHERE enabled ORDER BY id")
        for srv in servers:
            snap = await db.get_snapshot(f"unraid:{srv['id']}:docker")
            st: dict[str, Any] = {"server": srv["name"], "containers": 0}
            if snap is None:
                st.update(ok=False, error="no container list from the Unraid API yet (Unraid › Overview › Connection)")
                inv[str(srv["id"])] = st
                continue
            details: dict[str, dict[str, Any]] = {}
            if srv["docker_url"]:
                try:
                    details = await self.docker_details(srv["docker_url"])
                    st["docker_api"] = "ok"
                except Exception as exc:  # noqa: BLE001
                    st["docker_api"] = _docker_err(exc)
            else:
                st["docker_api"] = ("not set up: the registry's current image for each tag is scanned, which can "
                                    "differ from the one running - add a Docker API (docker-socket-proxy with "
                                    "CONTAINERS=1 and IMAGES=1) under Settings › Unraid servers")
            for c in snap:
                cname = str((c.get("names") or ["?"])[0]).lstrip("/")
                image = str(c.get("image") or "")
                if not image:
                    continue
                d = details.get(cname) or {}
                img_name = parse_image(d.get("image") if d.get("image") and not str(d["image"]).startswith("sha256:") else image)
                if excl and matches(excl, img_name.names() + [cname, image]):
                    continue
                digest = d.get("digest")
                key = digest or d.get("image_id") or img_name.full + ":" + (img_name.tag or "")
                t = targets.get(key)
                if t is None:
                    t = targets[key] = Target(key, image, img_name, digest=digest, image_id=d.get("image_id"),
                                              docker_url=srv["docker_url"] or None, labels=d.get("labels") or {},
                                              env=d.get("env") or {}, local_only=bool(d) and not digest)
                    if not digest:
                        t.notes.append("exact image unknown: the registry's current image for the tag was scanned"
                                       if not d else "no registry digest (built locally?): exported through the Docker API")
                t.containers.append({"server": srv["name"], "server_id": srv["id"], "name": cname,
                                     "state": c.get("state")})
                st["containers"] += 1
            st["ok"] = True
            inv[str(srv["id"])] = st
        for image in patterns(self.s.vuln_images):
            n = parse_image(image)
            key = (n.digest or "") or n.full + ":" + (n.tag or "")
            if key not in targets:
                targets[key] = Target(key, image, n, digest=n.digest)
            targets[key].containers.append({"server": "", "server_id": None, "name": "(listed image)", "state": None})
        await self.save_status(inventory=inv)
        return list(targets.values())

    async def docker_details(self, docker_url: str) -> dict[str, dict[str, Any]]:
        """{container name: {image, image_id, digest, labels, env}} from a (read-only) Docker API."""
        out: dict[str, dict[str, Any]] = {}
        async with httpx.AsyncClient(base_url=docker_url.rstrip("/"), timeout=httpx.Timeout(20.0, connect=5.0)) as c:
            r = await c.get("/containers/json", params={"all": "1"})
            r.raise_for_status()
            images: dict[str, dict[str, Any]] = {}
            failed: list[Exception] = []
            containers = r.json()
            for ctr in containers:
                iid = ctr.get("ImageID")
                if iid and iid not in images:
                    try:  # one image that can't be read (removed meanwhile) does not cost the others their digest
                        ri = await c.get(f"/images/{iid}/json")
                        ri.raise_for_status()
                        images[iid] = ri.json()
                    except httpx.HTTPStatusError as exc:
                        images[iid] = {}
                        failed.append(exc)
            if failed and not any(images.values()):
                raise failed[0]  # none at all: the proxy refuses /images (IMAGES=1 missing)
            for ctr in containers:
                iid = ctr.get("ImageID")
                info = images.get(iid) or {}
                name = parse_image(str(ctr.get("Image") or ""))
                digests = [d for d in info.get("RepoDigests") or [] if "@" in d]
                mine = [d for d in digests if parse_image(d).full == name.full]
                cfg = info.get("Config") or {}
                env = dict(e.split("=", 1) for e in cfg.get("Env") or [] if "=" in e)
                entry = {"image": ctr.get("Image"), "image_id": iid, "digest": (mine or digests or [""])[0].split("@")[-1] or None,
                         "labels": cfg.get("Labels") or {}, "env": env}
                for n in ctr.get("Names") or []:
                    out[str(n).lstrip("/")] = entry
        return out

    # ----------------------------------------------------------------- scans ---
    def sbom_path(self, t: Target) -> Path:
        return self.base / "sbom" / f"{safe_name(t.key)}.json"

    def syft_sources(self, t: Target) -> list[tuple[str, str, dict[str, str]]]:
        """(label, syft source argument, extra env) in the order to try, per Settings › Image source."""
        mode = self.s.vuln_image_source
        out: list[tuple[str, str, dict[str, str]]] = []
        reg_digest = f"{t.name.full}@{t.digest}" if t.digest else None
        reg_tag = f"{t.name.full}:{t.name.tag}" if t.name.tag else None
        docker = None
        if t.docker_url and t.image_id:
            host = re.sub(r"^https?://", "tcp://", t.docker_url.rstrip("/"))
            docker = ("Docker API export", f"docker:{t.image_id}", {"DOCKER_HOST": host})
        if mode in ("auto", "registry") and reg_digest:
            out.append(("registry (exact digest)", f"registry:{reg_digest}", {}))
        if mode in ("auto", "docker") and docker:
            out.append(docker)
        if mode in ("auto", "registry") and not reg_digest and reg_tag and not t.local_only:
            out.append(("registry (current image of the tag)", f"registry:{reg_tag}", {}))
        return out

    async def build_sbom(self, t: Target) -> tuple[str, int]:
        env, path = self.tool_env(), self.sbom_path(t)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        errors = []
        for label, src, extra in self.syft_sources(t):
            try:
                args = [self.s.vuln_syft_path or "syft", "scan", src, "-o", f"syft-json={tmp}",
                        *shlex.split(self.s.vuln_syft_args or "")]
                await run_tool(args, {**env, **extra}, self.timeout())
                doc = json.loads(tmp.read_text())
                tmp.replace(path)
                return label, len(doc.get("artifacts") or [])
            except (ToolError, ValueError, OSError) as exc:
                errors.append(f"{label}: {exc}")
            finally:
                tmp.unlink(missing_ok=True)
        if not errors:
            raise ToolError("no way to get this image: " + ("the Docker API knows no registry digest and the image "
                            "source setting leaves out the Docker API" if t.local_only else
                            "set Settings › Container vulnerabilities › Image source to auto"))
        raise ToolError(" · ".join(errors))

    def sbom_packages(self, t: Target) -> list[dict[str, str]]:
        try:
            doc = json.loads(self.sbom_path(t).read_text())
        except (OSError, ValueError):
            return []
        return [{"name": a.get("name"), "version": a.get("version"), "type": a.get("type")} for a in doc.get("artifacts") or []]

    async def match(self, t: Target) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        args = [self.s.vuln_grype_path or "grype", f"sbom:{self.sbom_path(t)}", "-o", "json", "--by-cve",
                *shlex.split(self.s.vuln_grype_args or "")]
        doc = json.loads(await run_tool(args, self.tool_env(), self.timeout()))
        if not isinstance(doc, dict) or "matches" not in doc:
            raise ToolError("Grype's answer has no 'matches' - unexpected output format")
        return parse_grype(doc), (doc.get("descriptor") or {}).get("db") or {}

    async def app_checks(self, client: httpx.AsyncClient, osv: list[Source], t: Target,
                         checks: list[AppCheck]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Own checks for this image: ([findings], [{line, version, from, error}])."""
        found, info = [], []
        mine = [c for c in checks if matches(c.images, t.names())]
        if not mine:
            return [], []
        data = self.image_meta(t)
        for chk in mine:
            version, where = chk.version(data)
            entry = {"line": chk.line, "check": chk.text, "from": where, "version": version, "error": None}
            if not version:
                entry["error"] = f"no version found in the {where}"
            elif not osv:
                entry["error"] = "no osv source (Settings › Container vulnerabilities › Sources)"
            else:
                errors = []
                for src in osv:
                    try:
                        body = {"package": {"ecosystem": chk.ecosystem, "name": chk.package}, "version": version}
                        doc = json.loads(decode(await self.fetch(client, src, src.url, body)))
                        found += osv_findings(doc, chk, version)
                        entry["source"] = src.url
                        await self.source_status("osv", True, url=src.url)
                        errors = []
                        break
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"line {src.line} {src.label()}: {_err(exc)}")
                if errors:
                    entry["error"] = "; ".join(errors)[:600]
                    await self.source_status("osv", False, error=entry["error"])
            info.append(entry)
        return found, info

    def image_meta(self, t: Target) -> dict[str, Any]:
        """Labels, environment, tag and packages of an image: from the Docker API, else the image config Syft keeps
        in the package list (works without a Docker API, once the image was read)."""
        data = {"env": t.env, "labels": t.labels, "tag": t.name.tag, "packages": self.sbom_packages(t)}
        try:
            data["os_version"] = (json.loads(self.sbom_path(t).read_text()).get("distro") or {}).get("versionID")
        except (OSError, ValueError):
            pass
        if not t.labels and not t.env:
            try:
                src = json.loads(self.sbom_path(t).read_text()).get("source") or {}
                meta = src.get("metadata") or src.get("target") or {}
                cfg = meta.get("config")
                if isinstance(cfg, str):
                    import base64
                    cfg = json.loads(base64.b64decode(cfg))
                c = (cfg or {}).get("config") or {}
                data["labels"] = c.get("Labels") or meta.get("labels") or {}
                data["env"] = dict(e.split("=", 1) for e in c.get("Env") or [] if "=" in e)
            except (OSError, ValueError, TypeError):
                pass
        return data

    def version_of(self, t: Target) -> dict[str, Any]:
        text = self.s.vuln_version_sources if (self.s.vuln_version_sources or "").strip() else \
            Settings.model_fields["vuln_version_sources"].default
        try:
            rules = parse_version_sources(text)
        except ValueError:
            rules = parse_version_sources(Settings.model_fields["vuln_version_sources"].default)
        return detect_version(self.image_meta(t), t.name, rules)

    async def update_check(self, client: httpx.AsyncClient, t: Target, old: dict[str, Any] | None) -> dict[str, Any] | None:
        """Is there a newer image for the tag? Compares the running digest with the registry's (a HEAD request,
        which Docker Hub does not count as a pull)."""
        if not t.digest or not t.name.tag:
            return None
        if old and time.time() - (old.get("checked") or 0) < UPDATE_CHECK_HOURS * 3600 and old.get("running") == t.digest:
            return old
        out: dict[str, Any] = {"checked": time.time(), "running": t.digest}
        try:
            latest = await registry_digest(client, t.name, self.s)
            out.update(latest=latest, available=latest != t.digest)
        except Exception as exc:  # noqa: BLE001
            out["error"] = _err(exc)
        return out

    async def store(self, t: Target, findings: list[dict[str, Any]], **cols: Any) -> None:
        pool = db.pool()
        old = {(r["vuln"], r["package"], r["version"]): r["first_seen"] for r in await pool.fetch(
            "SELECT vuln, package, version, first_seen FROM vuln_findings WHERE image_key = $1", t.key)}
        async with pool.acquire() as con, con.transaction():
            await con.execute(
                "INSERT INTO vuln_images (key, image, repo, digest, containers, notes, seen_at) VALUES ($1, $2, $3, $4, $5, $6, now()) "
                "ON CONFLICT (key) DO UPDATE SET image = EXCLUDED.image, repo = EXCLUDED.repo, digest = EXCLUDED.digest, "
                "containers = EXCLUDED.containers, notes = EXCLUDED.notes, seen_at = now()",
                t.key, t.image, t.name.full, t.digest, t.containers, t.notes)
            sets = ", ".join(f"{k} = ${i}" for i, k in enumerate(cols, 2))
            if sets:
                await con.execute(f"UPDATE vuln_images SET {sets} WHERE key = $1", t.key, *cols.values())
            if findings is not None and cols.get("status") == "ok":
                await con.execute("DELETE FROM vuln_findings WHERE image_key = $1", t.key)
                await con.executemany(
                    "INSERT INTO vuln_findings (image_key, vuln, package, version, pkg_type, aliases, cves, severity, cvss, "
                    "cvss_source, kev, epss, epss_pct, fix_versions, fix_state, url, description, locations, source, "
                    "first_seen, upstream, matched) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,"
                    "coalesce($20, now()), $21, $22) "
                    "ON CONFLICT DO NOTHING",
                    [(t.key, f["vuln"], f["package"], f["version"], f["pkg_type"], f["aliases"], f["cves"], f["severity"],
                      f["cvss"], f["cvss_source"], f["kev"], f["epss"], f["epss_pct"], f["fix_versions"], f["fix_state"],
                      f["url"], f["description"], f["locations"], f["source"], old.get((f["vuln"], f["package"], f["version"])),
                      f.get("upstream") or None, f.get("matched") or None)
                     for f in findings])

    # ------------------------------------------------------------------ run ---
    async def cycle(self, rebuild: bool = False) -> None:
        """One full pass: tools, database, sources, inventory, SBOMs where due, matching, own checks, alerts."""
        started = time.time()
        await self.save_status(running=True, started=started, phase="checking Grype and Syft", error=None)
        try:
            if not await self.tools():
                return
            await self.save_status(phase="updating the vulnerability database")
            await self.update_db()
            srcs, src_err = sources(self.s)
            await self.save_status(sources_error=src_err)
            try:
                checks = parse_app_checks(self.s.vuln_app_checks)
                await self.save_status(app_checks_error=None)
            except ValueError as exc:
                checks = []
                await self.save_status(app_checks_error=str(exc))
            headers = {"User-Agent": USER_AGENT}
            async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers=headers) as client:
                await self.save_status(phase="downloading the known-exploited list")
                await self.refresh_kev(client, srcs.get("kev", []), force=rebuild)
                await self.save_status(phase="listing containers")
                targets = await self.inventory()
                rows = {r["key"]: dict(r) for r in await db.pool().fetch("SELECT * FROM vuln_images")}
                tool_ver = (self.status.get("tools") or {}).get("syft", {}).get("version")
                # no usable database: the package lists are still made, matching waits (the database alert says why)
                db_ok = bool((self.status.get("db") or {}).get("valid"))
                for i, t in enumerate(targets, 1):
                    await self.save_status(phase=f"scanning {t.image} ({i}/{len(targets)})")
                    row = rows.get(t.key) or {}
                    sbom_age = time.time() - row["sbom_at"].timestamp() if row.get("sbom_at") else None
                    cols: dict[str, Any] = {}
                    try:
                        if rebuild or sbom_age is None or sbom_age > self.s.vuln_rescan_days * 86400 or \
                                not self.sbom_path(t).exists() or row.get("sbom_tool") != tool_ver:
                            how, n = await self.build_sbom(t)
                            cols.update(sbom_at=datetime.now(timezone.utc), sbom_source=how, sbom_tool=tool_ver, packages=n)
                        cols["version"] = self.version_of(t)
                        if not db_ok:
                            cols.update(status="pending", error="waiting for the vulnerability database (see Problems)")
                            await self.store(t, [], **cols)
                            continue
                        findings, dbinfo = await self.match(t)
                        app, app_info = await self.app_checks(client, srcs.get("osv", []), t, checks)
                        upd = await self.update_check(client, t, row.get("update_info"))
                        cols.update(status="ok", error=None, errors=0, matched_at=datetime.now(timezone.utc),
                                    db_built=str((dbinfo.get("status") or dbinfo).get("built") or "") or None,
                                    app=app_info, update_info=upd)
                        await self.store(t, findings + app, **cols)
                        await self.problem(f"image:{t.key}", True)
                    except (ToolError, OSError, ValueError) as exc:
                        n_err = (row.get("errors") or 0) + 1
                        cols.update(status="error", error=str(exc)[:1500], errors=n_err, tried_at=datetime.now(timezone.utc))
                        await self.store(t, [], **cols)
                        log.warning("vulnerability scan of %s failed: %s", t.image, exc)
                        if n_err >= 2:  # once can be a registry hiccup
                            await self.problem(f"image:{t.key}", False, f"Can't scan container image {t.image}",
                                               f"The last {n_err} scans of {t.image} (containers: "
                                               f"{', '.join(c['name'] for c in t.containers)}) failed - its "
                                               f"vulnerabilities are unknown. Last error: {str(exc)[:700]}",
                                               severity="low")
                await self.save_status(phase="looking up EPSS and CVSS scores")
                await self.enrich(client, srcs)
            await self.forget(targets)
            await self.save_status(last_scan=time.time(), duration=round(time.time() - started), phase=None)
            await self.evaluate()
        except Exception as exc:  # noqa: BLE001 - shown on the page, retried next time
            log.exception("vulnerability scan failed")
            await self.save_status(error=f"{type(exc).__name__}: {exc}"[:600], phase=None)
        finally:
            await self.save_status(running=False, last_try=time.time())

    async def enrich(self, client: httpx.AsyncClient, srcs: dict[str, list[Source]]) -> None:
        pool = db.pool()
        cves = {c for (c,) in await pool.fetch("SELECT DISTINCT unnest(cves) FROM vuln_findings")}
        await self.enrich_epss(client, srcs.get("epss", []), cves)
        missing = {c for (c,) in await pool.fetch(
            "SELECT DISTINCT unnest(cves) FROM vuln_findings WHERE cvss IS NULL AND NOT kev")}
        await self.enrich_cvss(client, srcs.get("cvss", []), missing)

    async def forget(self, targets: list[Target]) -> None:
        """Images no container uses any more (gone for 2 days - not after one failed listing): removed, alerts closed."""
        pool = db.pool()
        keep = [t.key for t in targets]
        gone = await pool.fetch("DELETE FROM vuln_images WHERE NOT (key = ANY($1::text[])) AND seen_at < now() - interval '2 days' "
                                "RETURNING key, repo", keep)
        for r in gone:
            await pool.execute("DELETE FROM vuln_findings WHERE image_key = $1", r["key"])
            (self.base / "sbom" / f"{safe_name(r['key'])}.json").unlink(missing_ok=True)
            await self.problem(f"image:{r['key']}", True)
        live = {r["repo"] for r in await pool.fetch("SELECT DISTINCT repo FROM vuln_images")}
        stale = [r["fingerprint"] for r in await pool.fetch(
            "SELECT DISTINCT fingerprint FROM alerts WHERE rule = $1 AND status <> 'closed'", RULE)
            if r["fingerprint"].removeprefix("vuln:") not in live]
        if stale:
            await close_alerts(RULE, stale, "no container uses this image any more")

    async def evaluate(self) -> None:
        """Alerts from the stored findings (also hourly between scans, so changed thresholds / exceptions apply soon)."""
        pool = db.pool()
        pol = Policy.of(self.s)
        kev = set(await db.kv_get("vulnscan:kev", []) or [])
        epss = {r["id"]: r["value"] for r in await pool.fetch("SELECT id, value FROM vuln_cache WHERE kind = 'epss'")}
        cvss = {r["id"]: r["value"] for r in await pool.fetch("SELECT id, value FROM vuln_cache WHERE kind = 'cvss'")}
        images = [dict(r) for r in await pool.fetch("SELECT * FROM vuln_images ORDER BY image")]
        today = date.today()
        by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for img in images:
            by_repo[img["repo"]].append(img)
        for repo, imgs in by_repo.items():
            hits: list[tuple[dict[str, Any], dict[str, Any], str]] = []
            for img in imgs:
                n = parse_image(img["image"])
                names = n.names() + [c["name"] for c in img["containers"] or []]
                rows = [dict(r) for r in await pool.fetch("SELECT * FROM vuln_findings WHERE image_key = $1", img["key"])]
                updates = []
                for f in rows:
                    e = [epss[c] for c in f["cves"] if c in epss and "epss" in epss[c]]
                    if e and (f["epss"] is None or max(x["epss"] for x in e) > f["epss"]):
                        f["epss"], f["epss_pct"] = max(x["epss"] for x in e), max((x.get("pct") or 0) for x in e)
                    if f["cvss"] is None:
                        sc = [cvss[c]["cvss"] for c in f["cves"] if c in cvss and cvss[c].get("cvss") is not None]
                        if sc:
                            f["cvss"], f["cvss_source"] = max(sc), "NVD lookup"
                    f["kev"] = bool(f["kev"] or any(c in kev for c in f["cves"]))
                    alert, ignored, why = pol.judge(f, names, today)
                    updates.append((img["key"], f["vuln"], f["package"], f["version"], f["epss"], f["epss_pct"], f["cvss"],
                                    f["cvss_source"], f["kev"], alert, ignored, why))
                    if alert:
                        hits.append((img, f, why))
                await pool.executemany(
                    "UPDATE vuln_findings SET epss = $5, epss_pct = $6, cvss = $7, cvss_source = $8, kev = $9, alerted = $10, "
                    "ignored = $11, why = $12 WHERE image_key = $1 AND vuln = $2 AND package = $3 AND version = $4", updates)
            await self.alert(repo, imgs, hits)
        await self.save_status(last_eval=time.time())

    async def alert(self, repo: str, imgs: list[dict[str, Any]], hits: list[tuple[dict[str, Any], dict[str, Any], str]]) -> None:
        fp = f"vuln:{repo}"
        if not hits:
            await close_alerts(RULE, [fp], "no vulnerability above your threshold any more (updated image, new "
                               "threshold or exception)")
            return
        uniq: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {}
        pkgs: dict[str, list[str]] = defaultdict(list)
        for img, f, why in hits:
            uniq.setdefault(f["vuln"], (img, f, why))
            if f["package"] not in pkgs[f["vuln"]]:
                pkgs[f["vuln"]].append(f["package"])
        ordered = sorted(uniq.values(), key=lambda h: (not h[1]["kev"], -(score_of(h[1]) or 0)))
        top = max((level_of(f) for _, f, _ in ordered), key=LEVELS.index)
        n_kev = sum(1 for _, f, _ in ordered if f["kev"])
        image = imgs[0]["image"]
        ctrs = sorted({f"{c['name']}" + (f" ({c['server']})" if c.get("server") else "") for img in imgs
                       for c in img["containers"] or [] if c.get("server_id") is not None})
        upd = next((i["update_info"] for i in imgs if (i.get("update_info") or {}).get("available")), None)
        rating = Rating(top, f"highest finding: {_finding_short(ordered[0][1])}")
        if n_kev:
            rating.note(f"{n_kev} actively exploited (CISA KEV)")
        lines = [f"- {_finding_short(f)} – {why}" + (f"; fixed in {', '.join(f['fix_versions'][:3])}" if f["fix_versions"] else "")
                 + _also(f, pkgs[f["vuln"]]) for _, f, why in ordered[:15]]
        more = f"\n- … and {len(ordered) - 15} more (Vulnerabilities page)" if len(ordered) > 15 else ""
        fix = ("A newer image is available for this tag: update the container (Unraid › Docker tab › the container › "
               "'apply update', or Check for Updates first). Most findings are fixed by the image maintainer's next build."
               if upd else "Update the container to the newest image (Unraid › Docker tab › Check for Updates › apply "
               "update). If no newer image fixes it, check the project's release notes, or record an exception under "
               "Settings › Container vulnerabilities › Exceptions.")
        desc = (f"Image {image}" + (f" used by: {', '.join(ctrs)}" if ctrs else " (Settings › Container vulnerabilities › "
                "Extra images)") + ".\n\n" + "\n".join(lines) + more + f"\n\n{fix}")
        title = (f"Container {ctrs[0].split(' (')[0]}" if len(ctrs) == 1 else f"Image {image}") + (f": {len(ordered)} "
                 f"vulnerabilit{'y' if len(ordered) == 1 else 'ies'}") + (f" ({n_kev} actively exploited)" if n_kev else "")
        await raise_alert(RULE, rating, title, fp, desc, mode="max", count=len(ordered),
                          data={"image": image, "repo": repo, "containers": ctrs, "kev": n_kev,
                                "vulns": [f["vuln"] for _, f, _ in ordered[:50]], "update_available": bool(upd)})

    async def run(self) -> None:
        await asyncio.sleep(90)
        await self.load_status()
        if self.status.get("running"):
            await self.save_status(running=False, phase=None)  # a restart in the middle of a scan
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("vulnerability scanner loop failed")
            try:
                await asyncio.wait_for(self.wake.wait(), 20)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()

    async def tick(self) -> None:
        if not self.s.vuln_scan_enabled:
            if self.status.get("enabled") is not False:
                await self.save_status(enabled=False)
            return
        if self.status.get("enabled") is not True:
            await self.save_status(enabled=True)
        req = await db.kv_get("vulnscan:request")
        if req:
            await db.pool().execute("DELETE FROM kv WHERE key = 'vulnscan:request'")
        now = time.time()
        if req or now - (self.status.get("last_try") or 0) >= self.s.vuln_recheck_hours * 3600:
            await self.cycle(rebuild=bool((req or {}).get("rebuild")))
        elif now - (self.status.get("last_eval") or 0) >= 3600:
            await self.evaluate()


def _finding_short(f: dict[str, Any]) -> str:
    s = score_of(f)
    score = (f"CVSS {s:.1f}" if f.get("cvss") is not None else f"{f.get('severity')}") if s is not None else "no score"
    extra = []
    if f.get("kev"):
        extra.append("actively exploited")
    if f.get("epss") is not None:
        extra.append(f"EPSS {f['epss']:.0%}")
    return f"{f['vuln']} in {f['package']} {f['version']} ({score}{', ' + ', '.join(extra) if extra else ''})"


def _also(f: dict[str, Any], names: list[str]) -> str:
    """'; source package dotnet10 10.0.113-… < 10.0.114-… (also: aspnetcore-runtime-10.0, …)' for an alert line."""
    m = f.get("matched") or {}
    out = ""
    if m.get("searched") and m.get("constraint"):
        out += f"; compared {m['searched']} with {m['constraint']}"
    others = [n for n in names if n != f["package"]]
    if others:
        out += f" (same fix also in {', '.join(others[:5])}{' …' if len(others) > 5 else ''})"
    return out


def _err(exc: BaseException) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, json.JSONDecodeError):
        return "the answer is not JSON - wrong address or format?"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.ConnectError):
        return f"can't connect ({exc or 'DNS / network / firewall'})"
    return str(exc) or type(exc).__name__


def _docker_err(exc: BaseException) -> str:
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 403:
        path = exc.request.url.path
        need = "IMAGES=1" if path.startswith("/images") else "CONTAINERS=1"
        return (f"refused ({path}): the docker-socket-proxy needs {need} - on Unraid: Docker tab › docker-socket-proxy "
                f"› Edit › add a variable {need.split('=')[0]} with value 1 › Apply. Without it the registry's current "
                "image for each tag is scanned instead of the exact one running")
    return f"{_err(exc)} - the registry's current image for each tag is scanned instead of the exact one running"


async def registry_digest(client: httpx.AsyncClient, name: ImageName, s: Settings) -> str:
    """Digest of ``name.tag`` in its registry (OCI distribution API, anonymous or with the registry login)."""
    host = "registry-1.docker.io" if name.registry == "docker.io" else name.registry
    url = f"https://{host}/v2/{name.repo}/manifests/{name.tag}"
    accept = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                        "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json"])
    r = await client.head(url, headers={"Accept": accept})
    if r.status_code == 401 and "bearer" in r.headers.get("www-authenticate", "").lower():
        params = dict(re.findall(r'(\w+)="([^"]*)"', r.headers["www-authenticate"]))
        realm = params.pop("realm", "")
        auth = None
        login_host = (s.vuln_registry_host or "docker.io").strip()
        if s.vuln_registry_user and s.vuln_registry_password and (
                login_host == name.registry or (login_host in DOCKER_HUB and name.registry == "docker.io")):
            auth = (s.vuln_registry_user, s.vuln_registry_password)
        t = await client.get(realm, params=params, auth=auth)
        t.raise_for_status()
        token = t.json().get("token") or t.json().get("access_token")
        r = await client.head(url, headers={"Accept": accept, "Authorization": f"Bearer {token}"})
    r.raise_for_status()
    digest = r.headers.get("docker-content-digest")
    if not digest:
        raise RuntimeError("the registry did not say the digest")
    return digest


async def test_sources(settings: Settings, text: str | None = None) -> list[dict[str, Any]]:
    """Try every source line (Settings › Container vulnerabilities › Test sources) and say what each one gave."""
    t = text if text is not None else settings.vuln_sources
    if not (t or "").strip():
        t = Settings.model_fields["vuln_sources"].default
    srcs = parse_sources(t)  # ValueError -> shown by the caller
    out = []
    probe_cve = "CVE-2021-44228"  # Log4Shell: in every list
    scanner = VulnScanner(settings)
    async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        for kind, lst in srcs.items():
            if not lst:
                out.append({"kind": kind, "line": None, "url": "", "ok": True, "result": "switched off"})
            for src in lst:
                entry = {"kind": kind, "line": src.line, "url": src.url}
                try:
                    if kind == "kev":
                        ids = extract_kev(src, await scanner.fetch(client, src, src.url))
                        entry.update(ok=len(ids) >= 10, result=f"{len(ids)} CVE ids" + (", including Log4Shell" if probe_cve in ids else ""))
                    elif kind == "epss":
                        url = src.url.replace("{cves}", probe_cve)
                        got = extract_epss(src, await scanner.fetch(client, src, url))
                        e = got.get(probe_cve)
                        entry.update(ok=bool(e), result=f"{probe_cve}: EPSS {e[0]:.1%}" if e else f"{len(got)} scores, none for {probe_cve}")
                    elif kind == "cvss":
                        sc = extract_cvss(src, await scanner.fetch(client, src, src.url.replace("{cve}", probe_cve)))
                        entry.update(ok=sc is not None, result=f"{probe_cve}: CVSS {sc}" if sc is not None else "no score at those paths")
                    else:
                        body = {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}, "version": "2.14.1"}
                        doc = json.loads(decode(await scanner.fetch(client, src, src.url, body)))
                        entry.update(ok=bool(doc.get("vulns")), result=f"log4j-core 2.14.1: {len(doc.get('vulns') or [])} vulnerabilities")
                except Exception as exc:  # noqa: BLE001
                    entry.update(ok=False, result=_err(exc))
                out.append(entry)
    return out
