"""Event enrichment: GeoIP country lookup and internal/external classification."""
from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from typing import Any

from .parsers.common import is_internal_ip

log = logging.getLogger(__name__)


class Enricher:
    def __init__(self, geoip_db: str = "", internal_networks: str = "") -> None:
        self.reader = None
        if geoip_db and os.path.exists(geoip_db):
            try:
                import geoip2.database

                self.reader = geoip2.database.Reader(geoip_db)
                log.info("GeoIP database loaded from %s", geoip_db)
            except Exception:  # noqa: BLE001
                log.exception("could not open GeoIP database %s", geoip_db)
        else:
            log.info("no GeoIP database at %r - country enrichment disabled", geoip_db)
        self.internal = [ipaddress.ip_network(n.strip(), strict=False) for n in internal_networks.split(",") if n.strip()]
        self.country = lru_cache(maxsize=65536)(self._country)

    def is_internal(self, ip: str | None) -> bool:
        return bool(ip) and is_internal_ip(ip, self.internal)

    def _country(self, ip: str) -> str | None:
        if self.reader is None or self.is_internal(ip):
            return None
        try:
            if self.reader.metadata().database_type.endswith("City"):
                return self.reader.city(ip).country.iso_code
            return self.reader.country(ip).country.iso_code
        except Exception:  # noqa: BLE001 - AddressNotFound etc.
            return None

    def enrich(self, ev: dict[str, Any]) -> None:
        if self.reader is None:
            return
        if ev.get("src_ip") and not ev.get("src_country"):
            ev["src_country"] = self.country(ev["src_ip"])
        if ev.get("dst_ip") and not ev.get("dst_country"):
            ev["dst_country"] = self.country(ev["dst_ip"])
