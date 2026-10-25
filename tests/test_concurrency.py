"""Concurrent registrations on one IP must never lose a counter increment."""

import asyncio
import threading

import pytest

from guardpost.ip.reputation import IPReputationEngine
from guardpost.storage.memory import MemoryStorage
from guardpost.storage.sqlite import SQLiteStorage

N = 60


@pytest.fixture
async def sqlite_storage(tmp_path):
    storage = SQLiteStorage(tmp_path / "gp.db")
    await storage.initialize()
    yield storage
    await storage.close()


async def test_concurrent_records_on_one_ip_sqlite(sqlite_storage):
    engine = IPReputationEngine(sqlite_storage)
    await asyncio.gather(*[
        engine.record_registration("198.51.100.7", is_suspicious=i % 3 == 0) for i in range(N)
    ])
    ip = await sqlite_storage.get_ip_reputation("198.51.100.7")
    net = await sqlite_storage.get_ip_reputation("198.51.100.0/24")
    assert ip.total_registrations == N
    assert ip.suspicious_registrations == N // 3
    assert net.total_registrations == N
    assert net.suspicious_registrations == N // 3


async def test_concurrent_records_on_one_subnet_sqlite(sqlite_storage):
    engine = IPReputationEngine(sqlite_storage)
    await asyncio.gather(*[
        engine.record_registration(f"203.0.113.{i}", is_suspicious=False) for i in range(1, N + 1)
    ])
    net = await sqlite_storage.get_ip_reputation("203.0.113.0/24")
    assert net.total_registrations == N


async def test_concurrent_records_memory():
    storage = MemoryStorage()
    engine = IPReputationEngine(storage)
    await asyncio.gather(*[engine.record_registration("192.0.2.1", False) for _ in range(N)])
    assert (await storage.get_ip_reputation("192.0.2.1")).total_registrations == N


def test_two_connections_two_threads_no_lost_increment(tmp_path):
    """BEGIN IMMEDIATE serializes writers across connections (as across processes)."""
    path = tmp_path / "shared.db"
    asyncio.run(SQLiteStorage(path).initialize())
    per_thread = 40
    errors: list[BaseException] = []

    def worker():
        async def run():
            storage = SQLiteStorage(path)
            engine = IPReputationEngine(storage)
            try:
                for _ in range(per_thread):
                    await engine.record_registration("198.51.100.99", is_suspicious=False)
            finally:
                await storage.close()

        try:
            asyncio.run(run())
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    async def read():
        storage = SQLiteStorage(path)
        try:
            return await storage.get_ip_reputation("198.51.100.99")
        finally:
            await storage.close()

    assert asyncio.run(read()).total_registrations == 3 * per_thread


async def test_transaction_rolls_back_on_error(sqlite_storage):
    from guardpost.ip.reputation import IPReputationRecord

    def boom(conn):
        sqlite_storage._store_ip(conn, IPReputationRecord(ip_address="192.0.2.50"))
        raise RuntimeError("abort")

    with pytest.raises(RuntimeError):
        await sqlite_storage._write(boom)
    assert await sqlite_storage.get_ip_reputation("192.0.2.50") is None
