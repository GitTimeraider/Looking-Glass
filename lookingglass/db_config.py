"""Database connection entered in the setup wizard, stored encrypted in the data volume.

``<DATA_DIR>/database.conf`` (mode 0600) holds the connection as Fernet-encrypted JSON, using the same key file as
the other stored credentials. ``DATABASE_URL`` (or ``DATABASE_URL_FILE``) in the environment still works and takes
precedence; then this file is ignored.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from . import crypto

log = logging.getLogger(__name__)

SSL_MODES = ("prefer", "require", "disable")
FIELDS = ("host", "port", "database", "user", "password", "ssl")


def path(data_dir: str) -> Path:
    return Path(data_dir) / "database.conf"


def load(data_dir: str) -> dict[str, Any] | None:
    """The stored connection (asyncpg keyword arguments) or None when the wizard has not run yet."""
    p = path(data_dir)
    if not p.exists():
        return None
    raw = p.read_text().strip()
    plain = crypto.decrypt(raw)
    try:
        cfg = json.loads(plain) if plain else None
    except ValueError:
        cfg = None
    if not cfg:
        log.error("%s cannot be decrypted (encryption key replaced?) - the setup wizard asks for the database again", p)
        return None
    return cfg


def save(data_dir: str, cfg: dict[str, Any]) -> None:
    p = path(data_dir)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(crypto.encrypt(json.dumps({k: cfg[k] for k in FIELDS})))
    os.replace(tmp, p)
    log.info("database connection saved (encrypted) in %s", p)


def delete(data_dir: str) -> bool:
    p = path(data_dir)
    if p.exists():
        p.unlink()
        return True
    return False


def clean(form: dict[str, Any]) -> dict[str, Any]:
    """Validate wizard input; raises ValueError with a message for the user."""
    host = str(form.get("host") or "").strip()
    if not host or any(c in host for c in " /@?#"):
        raise ValueError("Enter the database server's host name or IP address.")
    try:
        port = int(form.get("port") or 5432)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be a number.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    database = str(form.get("database") or "").strip()
    user = str(form.get("user") or "").strip()
    if not database or not user:
        raise ValueError("Enter the database name and the user name.")
    ssl = str(form.get("ssl") or "prefer")
    if ssl not in SSL_MODES:
        raise ValueError("Unknown SSL mode.")
    return {"host": host, "port": port, "database": database, "user": user,
            "password": str(form.get("password") or ""), "ssl": ssl}


def connect_kwargs(cfg: dict[str, Any]) -> dict[str, Any]:
    return {"host": cfg["host"], "port": cfg["port"], "database": cfg["database"], "user": cfg["user"],
            "password": cfg["password"] or None, "ssl": cfg["ssl"]}
