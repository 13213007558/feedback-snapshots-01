"""
Unit tests for the optional PostgreSQL TLS policy.

The asyncpg and aiopg drivers are replaced by fakes so that the tests can
capture the exact arguments handed to each driver when the pool is created.
"""
import asyncio
import ssl
import subprocess
import sys
import types

import pytest

from databases import Database, PostgresTLSPolicy, TLSPolicyError

APPROVED_HOST = "db.internal.example"


class FakeAsyncpgPool:
    def __init__(self):
        self.closed = False

    async def acquire(self):
        return None

    async def close(self):
        self.closed = True


class FakeAiopgPool:
    def __init__(self):
        self.closed = False

    async def acquire(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class FakeDriver:
    """
    A fake driver entry point. Records every create_pool call and can be
    configured to fail a number of times before returning a pool.
    """

    def __init__(self, pool_class):
        self.pool_class = pool_class
        self.pool_calls = []
        self.pools = []
        self.failures = 0

    async def create_pool(self, **kwargs):
        self.pool_calls.append(kwargs)
        if self.failures:
            self.failures -= 1
            raise OSError("simulated connection failure")
        pool = self.pool_class()
        self.pools.append(pool)
        return pool


def _fake_asyncpg_module(driver):
    module = types.ModuleType("asyncpg")
    connection_module = types.ModuleType("asyncpg.connection")
    connection_module.Connection = type("Connection", (), {})
    transaction_module = types.ModuleType("asyncpg.transaction")
    transaction_module.Transaction = type("Transaction", (), {})
    module.connection = connection_module
    module.transaction = transaction_module
    module.create_pool = driver.create_pool
    return module


def _fake_aiopg_module(driver):
    module = types.ModuleType("aiopg")
    connection_module = types.ModuleType("aiopg.connection")
    connection_module.Connection = type("Connection", (), {})
    module.connection = connection_module
    module.Pool = FakeAiopgPool
    module.Connection = connection_module.Connection
    module.create_pool = driver.create_pool
    return module


@pytest.fixture
def fake_drivers(monkeypatch):
    asyncpg = FakeDriver(FakeAsyncpgPool)
    aiopg = FakeDriver(FakeAiopgPool)
    monkeypatch.setitem(sys.modules, "asyncpg", _fake_asyncpg_module(asyncpg))
    monkeypatch.setitem(sys.modules, "aiopg", _fake_aiopg_module(aiopg))
    # The backends bind their driver at import time, so make sure they are
    # re-imported while the fake drivers are installed.
    for name in ("databases.backends.postgres", "databases.backends.aiopg"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    return {"asyncpg": asyncpg, "aiopg": aiopg}


@pytest.fixture(scope="session")
def ca_file(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls")
    ca_path = directory / "ca.pem"
    key_path = directory / "ca-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(ca_path),
            "-days", "1", "-nodes", "-subj", "/CN=databases-test-ca",
        ],
        check=True,
        capture_output=True,
    )
    return str(ca_path)


def run(coro):
    return asyncio.run(coro)


def make_policy(ca_file):
    return PostgresTLSPolicy(hostname=APPROVED_HOST, ca=ca_file)


def assert_full_verification(context):
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize(
    "scheme,driver_name,minsize",
    [
        ("postgres", "asyncpg", "min_size"),
        ("postgresql", "asyncpg", "min_size"),
        ("postgresql+aiopg", "aiopg", "minsize"),
        ("postgres+aiopg", "aiopg", "minsize"),
    ],
)
def test_policy_enforces_verification_on_selected_driver(
    fake_drivers, ca_file, scheme, driver_name, minsize
):
    """
    The same approved configuration must require certificate and hostname
    verification on both asyncpg and aiopg, whatever scheme alias or
    explicit driver selection is used.
    """
    policy = make_policy(ca_file)
    database = Database(
        f"{scheme}://user:secret@{APPROVED_HOST}:5432/appdb",
        tls_policy=policy,
        min_size=2,
        max_size=9,
    )
    run(database.connect())

    driver = fake_drivers[driver_name]
    other = "aiopg" if driver_name == "asyncpg" else "asyncpg"
    assert fake_drivers[other].pool_calls == []
    assert len(driver.pool_calls) == 1

    kwargs = driver.pool_calls[0]
    assert kwargs["host"] == APPROVED_HOST
    assert kwargs["database"] == "appdb"
    # The approved configuration keeps the regular pool parameters.
    assert kwargs[minsize] == 2
    # New connections must verify the trust chain and the target hostname.
    assert_full_verification(kwargs["ssl"])

    assert database.is_connected
    run(database.disconnect())
    assert not database.is_connected


def test_policy_rejects_conflicting_url_and_keyword_settings(fake_drivers, ca_file):
    """
    A connection URL and an application override that contradict each other
    must be reported, with their sources, before any pool is created.
    """
    policy = make_policy(ca_file)
    database = Database(
        f"postgresql://{APPROVED_HOST}/appdb?ssl=true",
        tls_policy=policy,
        ssl=False,
    )
    with pytest.raises(TLSPolicyError) as excinfo:
        run(database.connect())
    assert "keyword argument" in str(excinfo.value)
    assert "ssl" in str(excinfo.value)

    # The rejected attempt must not have called either driver.
    assert fake_drivers["asyncpg"].pool_calls == []
    assert fake_drivers["aiopg"].pool_calls == []
    assert not database.is_connected


def test_policy_rejects_url_disabling_tls(fake_drivers, ca_file):
    policy = make_policy(ca_file)
    database = Database(
        f"postgresql://{APPROVED_HOST}/appdb?sslmode=disable",
        tls_policy=policy,
        ssl=True,
    )
    with pytest.raises(TLSPolicyError) as excinfo:
        run(database.connect())
    assert "connection URL" in str(excinfo.value)
    assert fake_drivers["asyncpg"].pool_calls == []
    assert not database.is_connected


def test_policy_rejects_repeated_transport_option_in_url(fake_drivers, ca_file):
    policy = make_policy(ca_file)
    database = Database(
        f"postgresql://{APPROVED_HOST}/appdb?ssl=true&ssl=false",
        tls_policy=policy,
    )
    with pytest.raises(TLSPolicyError) as excinfo:
        run(database.connect())
    assert "repeated" in str(excinfo.value)
    assert "'ssl'" in str(excinfo.value)
    assert fake_drivers["asyncpg"].pool_calls == []
    assert not database.is_connected


def test_policy_rejects_unapproved_host(fake_drivers, ca_file):
    policy = make_policy(ca_file)
    database = Database(
        "postgresql://other.example/appdb",
        tls_policy=policy,
    )
    with pytest.raises(TLSPolicyError) as excinfo:
        run(database.connect())
    assert APPROVED_HOST in str(excinfo.value)
    assert "other.example" in str(excinfo.value)
    assert fake_drivers["asyncpg"].pool_calls == []
    assert not database.is_connected


def test_policy_rejects_unconfirmable_driver(fake_drivers, ca_file):
    policy = make_policy(ca_file)
    with pytest.raises(TLSPolicyError) as excinfo:
        Database(f"postgresql+unknown://{APPROVED_HOST}/appdb", tls_policy=policy)
    assert "postgresql+unknown" in str(excinfo.value)
    assert fake_drivers["asyncpg"].pool_calls == []
    assert fake_drivers["aiopg"].pool_calls == []


def test_policy_rejects_non_postgres_scheme(ca_file):
    policy = make_policy(ca_file)
    with pytest.raises(TLSPolicyError) as excinfo:
        Database("sqlite:///example.db", tls_policy=policy)
    assert "sqlite" in str(excinfo.value)


def test_pool_creation_failure_allows_retry(fake_drivers, ca_file):
    """
    A failed first pool creation leaves the database unconnected; retrying
    must hand the driver a pool configuration that still obeys the policy.
    """
    policy = make_policy(ca_file)
    database = Database(
        f"postgresql://{APPROVED_HOST}/appdb",
        tls_policy=policy,
        min_size=1,
    )
    driver = fake_drivers["asyncpg"]
    driver.failures = 1

    with pytest.raises(OSError):
        run(database.connect())
    assert not database.is_connected
    assert len(driver.pool_calls) == 1

    run(database.connect())
    assert database.is_connected
    assert len(driver.pool_calls) == 2
    for kwargs in driver.pool_calls:
        assert kwargs["host"] == APPROVED_HOST
        assert kwargs["min_size"] == 1
        assert_full_verification(kwargs["ssl"])

    run(database.disconnect())
    assert not database.is_connected


def test_postgres_without_policy_is_unchanged(fake_drivers):
    database = Database(f"postgresql://{APPROVED_HOST}/appdb?ssl=true&max_size=5")
    run(database.connect())
    kwargs = fake_drivers["asyncpg"].pool_calls[0]
    assert kwargs == {
        "host": APPROVED_HOST,
        "port": None,
        "user": None,
        "password": None,
        "database": "appdb",
        "max_size": 5,
        "ssl": True,
    }
    run(database.disconnect())


def test_sqlite_without_policy_still_works():
    async def main():
        database = Database("sqlite:///:memory:")
        await database.connect()
        try:
            assert await database.fetch_val("SELECT 1") == 1
        finally:
            await database.disconnect()

    run(main())
