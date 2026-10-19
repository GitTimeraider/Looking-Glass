"""Encryption at rest for stored credentials (API keys, secrets, passwords).

The Fernet key lives in a file in the data volume (``<DATA_DIR>/lookingglass.key``, mode 0600), never in the
database or the environment, so a database dump or backup on its own does not expose any credential.
``LG_ENCRYPTION_KEY_FILE`` can point to another location (e.g. a Docker secret).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)
PREFIX = "fernet:"
_fernet: Fernet | None = None


class KeyFileError(RuntimeError):
    pass


def init(data_dir: str) -> None:
    global _fernet
    path = Path(os.environ.get("LG_ENCRYPTION_KEY_FILE") or Path(data_dir) / "lookingglass.key")
    if path.exists():
        key = path.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except OSError as exc:
            raise KeyFileError(
                f"cannot create the encryption key file {path}: {exc}. Mount a writable volume at {data_dir} "
                "(see docker-compose.yml) or set LG_ENCRYPTION_KEY_FILE.") from exc
        log.warning("created new encryption key %s - back it up together with the database; without it stored "
                    "credentials cannot be decrypted", path)
    try:
        _fernet = Fernet(key)
    except ValueError as exc:
        raise KeyFileError(f"invalid encryption key in {path}") from exc


def encrypt(value: str) -> str:
    if not value:
        return ""
    if _fernet is None:
        raise KeyFileError("encryption not initialised")
    return PREFIX + _fernet.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str:
    if not value:
        return ""
    if not value.startswith(PREFIX):
        return value  # legacy plaintext; re-encrypted on the next save / startup migration
    if _fernet is None:
        raise KeyFileError("encryption not initialised")
    try:
        return _fernet.decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        log.error("a stored secret cannot be decrypted (wrong or replaced key file?) - re-enter it in Settings")
        return ""


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)
