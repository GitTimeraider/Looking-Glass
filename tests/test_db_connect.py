"""Startup while the database restarts: db.connect retries instead of crashing Looking Glass."""
from __future__ import annotations

import asyncio

import asyncpg
import pytest

from lookingglass import db


class FakeConn:
    def __init__(self, fail_schema: bool):
        self.fail_schema = fail_schema
        self.released = False

    async def execute(self, sql: str):
        if self.released:  # what asyncpg does once the broken connection went back to the pool
            raise asyncpg.InterfaceError("cannot call Connection.execute(): connection has been released back to the pool")
        if "advisory_lock" in sql or "advisory_unlock" in sql:
            return "SELECT 1"
        if self.fail_schema:
            self.released = True
            raise asyncpg.exceptions.ConnectionDoesNotExistError(
                "connection was closed in the middle of operation: terminating connection due to administrator command")
        return "CREATE"


class FakePool:
    def __init__(self, conn: FakeConn):
        self.conn, self.terminated = conn, False

    def acquire(self):
        pool = self

        class Ctx:
            async def __aenter__(self):
                return pool.conn

            async def __aexit__(self, *exc):
                return False
        return Ctx()

    def terminate(self):
        self.terminated = True


@pytest.fixture
def pools(monkeypatch):
    made: list[FakePool] = []

    async def create_pool(*args, **kwargs):
        made.append(FakePool(FakeConn(fail_schema=not made)))  # the first one loses its connection mid-schema
        return made[-1]

    async def no_sleep(_):
        return None

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    monkeypatch.setattr(db.asyncio, "sleep", no_sleep)
    yield made
    db._pool = None


def test_connect_retries_when_the_database_shuts_down_during_schema_setup(pools):
    p = asyncio.run(db.connect("postgresql://x"))
    assert len(pools) == 2 and p is pools[1]
    assert pools[0].terminated and not pools[1].terminated


def test_connect_without_retry_raises_the_real_error(pools):
    with pytest.raises(asyncpg.exceptions.ConnectionDoesNotExistError):  # not the follow-up "released back" error
        asyncio.run(db.connect("postgresql://x", retry=False))
