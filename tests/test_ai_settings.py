"""The AI analyst knows which Looking Glass settings really exist (and never sees secrets)."""
import asyncio
import json
import re
from pathlib import Path

from lookingglass import ai, app_config, db
from lookingglass.config import Settings


class _Pool:
    async def fetch(self, *_):
        return []


def _run(monkeypatch, **kw):
    monkeypatch.setattr(db, "pool", lambda: _Pool())
    s = Settings(ai_api_key="sk-real-key", smtp_password="hunter2", unifi_username="admin-rod",
                 ai_privacy_terms="secretproject", web_internet_alerts="through")
    return asyncio.run(ai.tool_looking_glass_settings(s, **kw)), s


def test_tabs_match_the_settings_page():
    html = Path("lookingglass/web/templates/settings.html").read_text()
    ui = {m.replace("&amp;", "&") for m in re.findall(r'<button data-t="[^"]+"[^>]*>([^<]+)</button>', html)}
    tabs = {t.split(" › ")[0] for t in ai.SETTINGS_TABS.values()}
    assert tabs <= ui, tabs - ui
    assert set(ai.SETTINGS_TABS) == set(app_config.GROUPS)


def test_overview_lists_every_setting_with_path_and_value(monkeypatch):
    out, _ = _run(monkeypatch)
    keys = {i["key"] for items in out["settings"].values() for i in items}
    assert keys == {f.key for f in app_config.FIELDS}
    web = next(i for i in out["settings"]["Settings › Data & detection"] if i["key"] == "web_internet_alerts")
    assert web["value"] == "through" and web["choices"] == ["through", "attacks", "all"]
    assert any("Alert filters" in p["path"] for p in out["other_pages"])
    assert out["alert_filters"] == [] and "not_configurable" in out


def test_secrets_and_private_values_are_hidden(monkeypatch):
    out, _ = _run(monkeypatch)
    text = json.dumps(out)
    for leaked in ("sk-real-key", "hunter2", "admin-rod", "secretproject"):
        assert leaked not in text


def test_search_returns_descriptions_or_says_it_does_not_exist(monkeypatch):
    out, _ = _run(monkeypatch, search="web scanners")
    items = [i for items in out["settings"].values() for i in items]
    assert any(i["key"] == "web_internet_alerts" and i["description"] for i in items)
    out, _ = _run(monkeypatch, search="exclude security.txt from scanner_probe")
    assert isinstance(out["settings"], str) and "does not exist" in out["settings"]


def test_analyst_is_told_to_use_it():
    assert "looking_glass_settings" in ai.TOOL_NAMES
    assert "Never invent a Looking Glass setting" in ai.SYSTEM_PROMPT
