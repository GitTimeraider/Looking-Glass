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


def test_setup_summary_names_what_is_set_up_and_what_lookingglass_log_is():
    s = Settings(swag_log_dir="/swag/log", swag_access_logs="nginx/lookingglass.log", swag_fail2ban_log="",
                 ai_notes="Looking Glass is only reachable over the VPN.")
    text = ai.setup_summary(s)
    assert "access: nginx/lookingglass.log" in text and "NOT Looking Glass's own traffic" in text
    not_set_up = text.split("NOT set up: ", 1)[1].split(" - ", 1)[0]
    assert "SWAG fail2ban" in not_set_up and "OPNsense API" in not_set_up and "SWAG logs" not in not_set_up
    assert "never report their missing data" in text
    assert "only reachable over the VPN" in text and "take them as fact" in text
    # no SWAG: nothing about its log files; no notes: no notes line
    plain = ai.setup_summary(Settings())
    assert "lookingglass.log" not in plain and "notes" not in plain
    # set up, yet nothing in 30 days: not running on the user's side, not a gap
    assert "no events at all in 30 days: fail2ban" in ai.setup_summary(Settings(swag_log_dir="/swag/log"), {"fail2ban"})


def test_system_prompt_carries_the_setup(monkeypatch):
    class Pool:
        async def fetch(self, sql, *args):
            if "NOT EXISTS" in sql:  # nothing from these in 30 days
                return [{"s": x} for x in args[0]]
            return [{"source": "nginx", "n": 5}]
    monkeypatch.setattr(db, "pool", lambda: Pool())
    # SWAG with its default fail2ban log, but fail2ban never wrote anything; OPNsense not set up (Suricata not counted)
    prompt = asyncio.run(ai.Analyst(Settings(swag_log_dir="/swag/log")).system_message(False))
    assert "{setup}" not in prompt and "Set up in Looking Glass: SWAG logs" in prompt
    assert "no events at all in 30 days: fail2ban -" in prompt and "suricata" not in prompt.split("30 days:")[1].split(" - ")[0]
    from lookingglass.app_config import BY_KEY, SettingsError, _coerce
    assert BY_KEY["ai_notes"].group == "ai"
    try:
        _coerce(BY_KEY["ai_notes"], "x" * 2001)
        raise AssertionError("too long notes accepted")
    except SettingsError:
        pass
