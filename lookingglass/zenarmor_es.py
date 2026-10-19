"""Minimal Elasticsearch-compatible endpoint for Zenarmor's "Stream Reporting Data to External Elasticsearch".

Zenarmor's syslog export needs a paid edition; Elasticsearch streaming also works on the free Home edition.
Zenarmor only needs a handful of endpoints: the product check (GET /), index probes/creation, alias and settings
probes and _bulk writes. The protocol shape follows github.com/rknightion/opnsense2otel (zenarmor receiver),
which documents what ipdrstreamer calls on the wire.
"""
from __future__ import annotations

import base64
import gzip
import hmac
import ipaddress
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import Settings
from .ingest import STATS, EventWriter
from .parsers.common import parse_networks
from .parsers.security import zen_family_from_index, zenarmor_record

log = logging.getLogger(__name__)

ES_VERSION = "8.11.3"
ES_HEADERS = {"X-Elastic-Product": "Elasticsearch"}
MAX_BODY = 64 * 1024 * 1024


def es_json(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers=ES_HEADERS)


def create_es_app(settings: Settings, writer: EventWriter) -> Starlette:
    indexes: set[str] = set()
    stats = {"docs": 0, "bulk": 0, "self": 0, "last": None, "peer": None}

    def peer_ok(request: Request) -> bool:
        allowed = parse_networks(settings.zenarmor_es_allowed or settings.syslog_allowed_senders)
        if not allowed:
            return True
        try:
            return any(ipaddress.ip_address(request.client.host) in n for n in allowed)
        except (ValueError, AttributeError):
            return False

    def auth_ok(request: Request) -> bool:
        if not settings.zenarmor_es_user:
            return True
        hdr = request.headers.get("authorization", "")
        if not hdr.lower().startswith("basic "):
            return False
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
        except ValueError:
            return False
        return hmac.compare_digest(user, settings.zenarmor_es_user) and hmac.compare_digest(pw, settings.zenarmor_es_password)

    async def handler(request: Request) -> Response:
        if not peer_ok(request):
            return es_json({"error": "forbidden"}, 403)
        if not auth_ok(request):
            return Response(status_code=401, headers={**ES_HEADERS, "WWW-Authenticate": 'Basic realm="elasticsearch"'})
        path = request.url.path
        method = request.method
        if path == "/_bulk" or path.endswith("/_bulk"):
            return await bulk(request, path)
        if path == "/":
            return es_json({"name": "lookingglass", "cluster_name": "elasticsearch", "cluster_uuid": "LookingGlassZenarmorRx01",
                            "version": {"number": ES_VERSION, "build_flavor": "default", "build_type": "tar",
                                        "build_hash": "64cf052f3b56b1fd4449f5454cb88aca7e739d9a",
                                        "build_date": "2023-12-08T11:33:53.634979452Z", "build_snapshot": False,
                                        "lucene_version": "9.8.0", "minimum_wire_compatibility_version": "7.17.0",
                                        "minimum_index_compatibility_version": "7.0.0"},
                            "tagline": "You Know, for Search"})
        if path.startswith("/_cat/indices") or path.startswith("/_cat/aliases"):
            return es_json([])
        if path == "/_aliases":
            return es_json({"acknowledged": True})
        if path.endswith("/_alias"):
            return es_json({})
        if path.endswith("/_settings"):
            idx = path.strip("/").removesuffix("/_settings").strip("/")
            return es_json({idx: {"settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0", "provided_name": idx}}}})
        idx = path.strip("/")
        if idx and not idx.startswith("_") and "/" not in idx:
            if method in ("HEAD", "GET"):
                if idx not in indexes:
                    return es_json({"error": {"type": "index_not_found_exception", "reason": "no such index"}, "status": 404}, 404)
                return es_json({idx: {"aliases": {}, "mappings": {}, "settings": {}}})
            if method == "PUT":
                if len(indexes) < 500:
                    indexes.add(idx)
                return es_json({"acknowledged": True, "shards_acknowledged": True, "index": idx})
            if method == "DELETE":
                indexes.discard(idx)
                return es_json({"acknowledged": True})
        log.debug("zenarmor ES: unhandled %s %s", method, path)
        return es_json({})

    async def bulk(request: Request, path: str) -> Response:
        started = time.monotonic()
        body = await request.body()
        if len(body) > MAX_BODY:
            return es_json({"error": "body too large"}, 413)
        if "gzip" in request.headers.get("content-encoding", ""):
            try:
                body = gzip.decompress(body)
            except OSError:
                return es_json({"error": "bad gzip body"}, 400)
        default_idx = path.strip("/").removesuffix("_bulk").strip("/").split("/")[0]
        peer = request.client.host if request.client else None
        lines = body.split(b"\n")
        items: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if not line:
                continue
            try:
                action = json.loads(line)
                op, meta = next(iter(action.items()))
            except (ValueError, StopIteration, AttributeError):
                continue
            idx = (meta or {}).get("_index") or default_idx
            if op in ("index", "create", "update") and i < len(lines):
                doc_line = lines[i].strip()
                i += 1
                try:
                    doc = json.loads(doc_line)
                except ValueError:
                    doc = None
                family = zen_family_from_index(idx or "")
                if isinstance(doc, dict) and family:
                    # drop records describing this very ingest connection (firewall -> our ES port)
                    if peer and doc.get("ip_src_saddr") == peer and str(doc.get("ip_dst_port")) == str(settings.zenarmor_es_port):
                        stats["self"] += 1
                    else:
                        ev = zenarmor_record(family, doc, now, host=peer, program="zenarmor-es")
                        writer.put(ev)
                        stats["docs"] += 1
                        STATS.by_source["zenarmor"] = STATS.by_source.get("zenarmor", 0) + 1
                        STATS.last_by_source["zenarmor"] = time.time()
            items.append({op: {"_index": idx, "_id": (meta or {}).get("_id") or "0", "_version": 1, "result": "created",
                               "_shards": {"total": 1, "successful": 1, "failed": 0}, "status": 201}})
        stats.update(bulk=stats["bulk"] + 1, last=time.time(), peer=peer)
        STATS.extra["zenarmor_es"] = dict(stats)
        return es_json({"took": int((time.monotonic() - started) * 1000), "errors": False, "items": items})

    return Starlette(routes=[Route("/{path:path}", handler, methods=["GET", "HEAD", "PUT", "POST", "DELETE"])])
