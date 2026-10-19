import json

import pytest
from fastapi.testclient import TestClient

from lookingglass import crypto, db_config
from lookingglass.config import Settings
from lookingglass.web.wizard import MAX_ATTEMPTS, Wizard

H = {"X-Looking-Glass": "1"}


def test_db_config_roundtrip_is_encrypted(tmp_path):
    crypto.init(str(tmp_path))
    cfg = db_config.clean({"host": "db", "port": "5432", "database": "lookingglass", "user": "lg", "password": "s3cret!"})
    db_config.save(str(tmp_path), cfg)
    p = db_config.path(str(tmp_path))
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    assert "s3cret" not in p.read_text() and p.read_text().startswith("fernet:")
    assert db_config.load(str(tmp_path)) == cfg
    assert db_config.connect_kwargs(cfg)["ssl"] == "prefer"
    assert db_config.delete(str(tmp_path)) and db_config.load(str(tmp_path)) is None


def test_db_config_unreadable_with_other_key(tmp_path):
    crypto.init(str(tmp_path / "a"))
    db_config.save(str(tmp_path), db_config.clean({"host": "db", "database": "x", "user": "y"}))
    crypto.init(str(tmp_path / "b"))
    assert db_config.load(str(tmp_path)) is None


@pytest.mark.parametrize("form", [
    {"host": "", "database": "x", "user": "y"},
    {"host": "db/x", "database": "x", "user": "y"},
    {"host": "db", "port": "99999", "database": "x", "user": "y"},
    {"host": "db", "database": "", "user": "y"},
    {"host": "db", "database": "x", "user": "y", "ssl": "maybe"},
])
def test_db_config_rejects(form):
    with pytest.raises(ValueError):
        db_config.clean(form)


def test_wizard_requires_code_and_header():
    wiz = Wizard(Settings(), need_db=True, need_admin=False)
    client = TestClient(wiz.app())
    assert client.get("/healthz").json() == {"status": "setup"}
    assert "First-time setup" in client.get("/anything").text
    assert client.post("/wizard/code", json={"code": wiz.code}).status_code == 403  # no CSRF header
    assert client.post("/wizard/code", json={"code": "nope"}, headers=H).status_code == 403
    r = client.post("/wizard/code", json={"code": wiz.code.lower().replace("-", " ")}, headers=H)
    assert r.status_code == 200 and r.json()["need_db"] is True
    # the database endpoint checks the code before touching the network
    r = client.post("/wizard/database", json={"code": "nope", "host": "10.255.255.1"}, headers=H)
    assert r.status_code == 403
    r = client.post("/wizard/database", json={"code": wiz.code, "host": "", "database": "x", "user": "y"}, headers=H)
    assert r.status_code == 400
    # admin step is refused while the database is missing
    r = client.post("/wizard/admin", json={"code": wiz.code, "username": "a", "password": "Long-enough-1"}, headers=H)
    assert r.status_code == 409
    assert json.dumps(client.get("/wizard/state").json()).find(wiz.code) == -1


def test_wizard_rotates_code_after_failures():
    wiz = Wizard(Settings(), need_db=True, need_admin=False)
    client = TestClient(wiz.app())
    first = wiz.code
    for _ in range(MAX_ATTEMPTS):
        client.post("/wizard/code", json={"code": "WRONG"}, headers=H)
    assert wiz.code != first
    assert client.post("/wizard/code", json={"code": first}, headers=H).status_code == 403
