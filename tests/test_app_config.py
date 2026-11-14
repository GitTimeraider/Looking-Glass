import asyncio
import os

import pytest

from lookingglass import app_config, crypto, db
from lookingglass.config import Settings


def test_crypto_roundtrip(tmp_path):
    crypto.init(str(tmp_path))
    key_file = tmp_path / "lookingglass.key"
    assert key_file.exists() and oct(key_file.stat().st_mode & 0o777) == "0o600"
    token = crypto.encrypt("sk-secret")
    assert token.startswith("fernet:") and "sk-secret" not in token
    assert crypto.decrypt(token) == "sk-secret"
    assert crypto.decrypt("legacy-plain") == "legacy-plain"
    crypto.init(str(tmp_path))  # existing key is reused
    assert crypto.decrypt(token) == "sk-secret"


def test_wrong_key_does_not_crash(tmp_path):
    crypto.init(str(tmp_path / "a"))
    token = crypto.encrypt("x")
    crypto.init(str(tmp_path / "b"))
    assert crypto.decrypt(token) == ""


@pytest.mark.parametrize("key,value", [
    ("syslog_allowed_senders", "not-an-ip"),
    ("opnsense_url", "192.168.1.1"),
    ("poll_interval", "5"),
    ("timezone", "Mars/Olympus"),
    ("firewall_log_pull", "sometimes"),
    ("opnsense_ca_pem", "hello"),
])
def test_validation_rejects(key, value):
    with pytest.raises(app_config.SettingsError):
        app_config._coerce(app_config.BY_KEY[key], value)


def test_validation_accepts():
    assert app_config._coerce(app_config.BY_KEY["syslog_allowed_senders"], "192.168.1.1, 10.0.0.0/8") == "192.168.1.1, 10.0.0.0/8"
    assert app_config._coerce(app_config.BY_KEY["poll_interval"], "60") == 60
    assert app_config._coerce(app_config.BY_KEY["ids_pull"], "false") is False


def test_public_view_never_contains_secrets():
    s = Settings(opnsense_api_key="very-secret", ai_api_key="sk-abc", smtp_password="pw")
    view = repr(app_config.public_view(s))
    assert "very-secret" not in view and "sk-abc" not in view and "'pw'" not in view
    fields = {f["key"]: f for f in app_config.public_view(s)["fields"]}
    assert fields["opnsense_api_key"]["is_set"] is True and "value" not in fields["opnsense_api_key"]


DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_env_import_save_and_encryption(tmp_path, monkeypatch):
    async def main():
        crypto.init(str(tmp_path))
        await db.connect(DSN)
        try:
            await db.pool().execute("DELETE FROM app_settings")
            monkeypatch.setenv("OPNSENSE_API_KEY", "from-env")
            s = Settings()
            await app_config.load(s)
            assert s.opnsense_api_key == "from-env"
            stored = await db.pool().fetchval("SELECT value FROM app_settings WHERE key = 'opnsense_api_key'")
            assert stored.startswith("fernet:") and "from-env" not in stored
            # env is ignored once stored
            monkeypatch.setenv("OPNSENSE_API_KEY", "changed-env")
            s2 = Settings()
            await app_config.load(s2)
            assert s2.opnsense_api_key == "from-env"
            # empty secret keeps, None clears
            assert await app_config.save(s2, {"opnsense_api_key": ""}) == []
            assert await app_config.save(s2, {"opnsense_api_key": None, "poll_interval": 45}) == ["opnsense_api_key", "poll_interval"]
            assert s2.opnsense_api_key == "" and s2.poll_interval == 45
        finally:
            await db.pool().execute("DELETE FROM app_settings")
            await db.close()
    asyncio.run(main())


def test_list_fields_one_per_line():
    from lookingglass import app_config
    f = app_config.BY_KEY["intel_allow"]
    assert f.kind == "list"
    assert app_config._coerce(f, " evil.example\n\n  203.0.113.5 ,evil.example;x.org\n") == "evil.example, 203.0.113.5, x.org"
    assert app_config._coerce(f, "") == ""
    nets = app_config.BY_KEY["syslog_allowed_senders"]
    assert app_config._coerce(nets, "192.168.1.1\n10.0.0.0/8") == "192.168.1.1, 10.0.0.0/8"
    import pytest
    with pytest.raises(app_config.SettingsError, match="not-an-ip"):
        app_config._coerce(nets, "192.168.1.1\nnot-an-ip")


def test_display_defaults():
    s = Settings()
    assert (s.theme, s.accent, s.nav_position, s.corners) == ("dark", "purple", "top", "square")
    assert (s.app_name, s.logo, s.favicon) == ("", "", "")
    view = {f["key"]: f for f in app_config.public_view(s)["fields"]}
    assert view["accent"]["default"] == "purple" and view["logo"]["default"] == ""


def test_image_fields():
    png = "data:image/png;base64,iVBORw0KGgo="
    f = app_config.BY_KEY["logo"]
    assert app_config._coerce(f, png) == png
    assert app_config._coerce(f, "") == ""
    assert app_config.image_bytes(png) == ("image/png", b"\x89PNG\r\n\x1a\n")
    assert app_config.image_bytes("data:image/x-icon;base64,AAAB")[0] == "image/x-icon"
    assert app_config.image_bytes("") is None
    for bad in ("data:text/html;base64,PGI+", "javascript:alert(1)", 'data:image/png;base64,AA" onerror="x',
                "data:image/png;base64,A", "data:image/png;base64," + "A" * (app_config.IMAGE_MAX_CHARS + 4)):
        with pytest.raises(app_config.SettingsError):
            app_config._coerce(f, bad)
    with pytest.raises(app_config.SettingsError):
        app_config._coerce(app_config.BY_KEY["app_name"], "x" * 61)
