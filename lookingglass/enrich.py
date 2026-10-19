"""Event enrichment: GeoIP country lookup and internal/external classification."""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

from .parsers.common import is_internal_ip, parse_networks

log = logging.getLogger(__name__)


class Enricher:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.reader = None
        self._geoip_path: str | None = None
        self.country = lru_cache(maxsize=65536)(self._country)
        self._refresh()

    def _refresh(self) -> None:
        """(Re)open the GeoIP database when its configured path changed."""
        path = self.settings.geoip_db
        if path == self._geoip_path:
            return
        self._geoip_path = path
        self.reader = None
        self.country.cache_clear()
        if path and os.path.exists(path):
            try:
                import geoip2.database

                self.reader = geoip2.database.Reader(path)
                log.info("GeoIP database loaded from %s", path)
            except Exception:  # noqa: BLE001
                log.exception("could not open GeoIP database %s", path)
        else:
            log.info("no GeoIP database at %r - country enrichment disabled", path)

    def is_internal(self, ip: str | None) -> bool:
        return bool(ip) and is_internal_ip(ip, parse_networks(self.settings.internal_networks))

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
        self._refresh()
        if self.reader is None:
            return
        if ev.get("src_ip") and not ev.get("src_country"):
            ev["src_country"] = self.country(ev["src_ip"])
        if ev.get("dst_ip") and not ev.get("dst_country"):
            ev["dst_country"] = self.country(ev["dst_ip"])
