"""Shutdown and crashes: a crashing background task is restarted, pollers stop before the database closes."""
import asyncio

from lookingglass import db


def test_a_crashing_background_task_is_restarted_not_the_app_stopped():
    from lookingglass import main as lgmain

    async def main():
        runs = []

        async def flaky():
            runs.append(1)
            if len(runs) < 3:
                raise RuntimeError("pool is closing")
            await asyncio.Event().wait()  # runs on

        real_sleep = asyncio.sleep

        async def no_wait(d):  # skip the restart pauses
            await real_sleep(0 if d >= 1 else d)
        lgmain.asyncio.sleep = no_wait
        try:
            task = asyncio.create_task(lgmain.keep_running("flaky", flaky))
            for _ in range(20):
                await real_sleep(0)
            assert len(runs) == 3 and not task.done()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert task.cancelled()
        finally:
            lgmain.asyncio.sleep = real_sleep

    asyncio.run(main())


def test_a_poller_is_stopped_when_its_supervisor_is_cancelled():
    from lookingglass import main as lgmain
    from lookingglass.config import Settings

    async def main():
        stopped = []

        class FakePoller:
            def __init__(self, *a):
                pass

            async def run(self):
                await asyncio.sleep(3600)

            async def stop(self):
                stopped.append(1)

        settings = Settings(secret_key="x" * 40)
        settings.opnsense_url, settings.opnsense_api_key, settings.opnsense_api_secret = "https://fw", "k", "s"
        real = lgmain.Poller
        lgmain.Poller = FakePoller
        try:
            task = asyncio.create_task(lgmain.opnsense_supervisor(settings, None))
            await asyncio.sleep(0.05)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert stopped == [1]
        finally:
            lgmain.Poller = real

    asyncio.run(main())


def test_closing_the_pool_does_not_wait_for_long_queries():
    class SlowPool:
        terminated = False

        async def close(self):
            await asyncio.sleep(3600)  # a 30-day query still running

        def terminate(self):
            self.terminated = True

    async def main():
        p = SlowPool()
        db._pool = p
        await db.close(timeout=0.05)
        assert p.terminated and db._pool is None

    asyncio.run(main())


def test_poller_job_survives_a_closing_database():
    from lookingglass.config import Settings
    from lookingglass.opnsense import Poller

    async def main():
        db._pool = None  # set_snapshot fails: "database not initialised" (like "pool is closing")
        s = Settings(secret_key="x" * 40)
        s.opnsense_url, s.opnsense_api_key, s.opnsense_api_secret = "https://fw", "k", "s"
        poller = Poller(s, None)

        async def job():
            raise RuntimeError("pool is closing")
        await poller._run_job("system", 30, job)  # logged, does not raise ("Task exception was never retrieved")
        assert poller.status["system"]["ok"] is False
        await poller.api.close()

    asyncio.run(main())
