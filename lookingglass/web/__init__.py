import hashlib
from pathlib import Path


def asset_version() -> str:
    """Cache-buster for style.css / app.js (?v=...): changes whenever their content does, not only with a new release,
    so browsers (phones above all) never keep showing an old stylesheet after an update."""
    h = hashlib.sha1()
    for name in ("style.css", "app.js"):
        h.update((Path(__file__).parent / "static" / name).read_bytes())
    return h.hexdigest()[:10]
