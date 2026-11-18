import asyncio
import os

import pytest

from lookingglass import blocking, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


def settings(**kw) -> Settings:
    return Settings(opnsense_url="https://192.168.1.1", opnsense_api_key="k", opnsense_api_secret="s",
                    block_alias="LG_block", **kw)


def test_normalise_and_refusals():
    assert blocking.normalise(" 203.0.113.7 ") == "203.0.113.7"
    assert blocking.normalise("203.0.113.7/32") == "203.0.113.7"
    assert blocking.normalise("203.0.113.9/24") == "203.0.113.0/24"
    assert blocking.normalise("2001:DB8::1") == "2001:db8::1"
    with pytest.raises(blocking.BlockError):
        blocking.normalise("example.com")
    s = settings(block_never="198.51.100.0/24")
    blocking.check(s, "203.0.113.7")
    for bad in ("127.0.0.1", "169.254.1.1", "198.51.100.20", "192.168.1.1", "10.0.0.0/8", "0.0.0.0/0"):
        with pytest.raises(blocking.BlockError):
            blocking.check(s, blocking.normalise(bad), allow_internal=True)
    with pytest.raises(blocking.BlockError, match="you are using"):
        blocking.check(s, "203.0.113.7", client_ip="203.0.113.7")
    with pytest.raises(blocking.BlockError, match="internal"):
        blocking.check(s, "192.168.1.50")
    blocking.check(s, "192.168.1.50", allow_internal=True)  # quarantine on request


class FakeAlias:
    """alias_util stand-in: remembers what is in the pf table."""
    table: set = set()
    calls: list = []

    def __init__(self, s, client=None):
        self.name = s.block_alias

    async def info(self):
        return {"exists": True, "type": "external"}

    async def list(self):
        return set(FakeAlias.table)

    async def add(self, a):
        FakeAlias.calls.append(("add", a))
        FakeAlias.table.add(a)

    async def delete(self, a):
        FakeAlias.calls.append(("delete", a))
        FakeAlias.table.discard(a)

    async def close(self):
        pass


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_block_sync_expiry_and_auto(monkeypatch):
    monkeypatch.setattr(blocking, "Alias", FakeAlias)
    FakeAlias.table, FakeAlias.calls = {"192.0.2.99"}, []  # .99: put there by someone else - never touched

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE blocks, alerts, snapshots")
            s = settings()
            b = await blocking.create(s, "203.0.113.7", 2, "test", by="me")
            assert b["status"] == "active" and b["in_alias"] and "203.0.113.7" in FakeAlias.table
            again = await blocking.create(s, "203.0.113.7", 0, "test", by="me")  # forever wins over 2 hours
            assert again["id"] == b["id"] and again["expires_at"] is None
            # OPNsense rebooted: the table is empty again - the sync puts it back
            FakeAlias.table.discard("203.0.113.7")
            st = await blocking.sync_once(s, FakeAlias(s))
            assert st["added"] == ["203.0.113.7"] and st["foreign"] == 1
            # an expired block is taken out
            await pool.execute("UPDATE blocks SET expires_at = now() - interval '1 minute'")
            st = await blocking.sync_once(s, FakeAlias(s))
            assert st["removed"] == ["203.0.113.7"] and FakeAlias.table == {"192.0.2.99"}
            assert await pool.fetchval("SELECT status FROM blocks") == "expired"
            # automatic: only the internet source of a new alert of the set severity, once
            for ip, sev in (("203.0.113.20", "critical"), ("192.168.1.30", "critical"), ("203.0.113.21", "high")):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                                   "('attack_chain', $1, 't', $2, $3::inet)", sev, ip, ip)
            assert await blocking.auto_block(s) == []  # off by default
            s.block_auto = True
            assert await blocking.auto_block(s) == ["203.0.113.20"]
            assert await blocking.auto_block(s) == []  # once per alert
            skipped = await pool.fetchval("SELECT data->'auto_block'->>'skipped' FROM alerts WHERE src_ip = '192.168.1.30'")
            assert skipped == "internal address"
            assert (await blocking.active_for(["203.0.113.20", "203.0.113.21"])).keys() == {"203.0.113.20"}
            bid = await pool.fetchval("SELECT id FROM blocks WHERE ip = '203.0.113.20'")
            out = await blocking.remove(s, bid, by="me")
            assert out["status"] == "removed" and "203.0.113.20" not in FakeAlias.table
            await pool.execute("TRUNCATE blocks, alerts")
        finally:
            await db.close()

    asyncio.run(main())
