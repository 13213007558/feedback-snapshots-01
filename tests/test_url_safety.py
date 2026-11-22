"""
Tests for the safe display of database connection URLs in diagnostics.

Deployment tooling may attach repr output of database objects to work orders,
so secrets must only ever reach the driver connection configuration and never
the public string representation or error messages.
"""
import asyncio
import functools
import sys
import types
from urllib.parse import quote

import pytest

from databases import Database, DatabaseURL


PASSWORD = "s3cr3tpass"
ENCODED_PASSWORD = quote("[password")
ENCODED_USERNAME = quote("user@example.com")
ORIGINAL_URL = (
    f"postgresql+asyncpg://{ENCODED_USERNAME}:{PASSWORD}"
    "@localhost:5432/appdb?ssl=true"
)


def async_adapter(wrapped_func):
    @functools.wraps(wrapped_func)
    def run_sync(*args, **kwargs):
        return asyncio.new_event_loop().run_until_complete(
            wrapped_func(*args, **kwargs)
        )

    return run_sync


CAPTURED_POOL_KWARGS: dict = {}


def _install_stub_asyncpg():
    """Register a minimal asyncpg stub so no real driver install is needed.

    The backend module binds ``asyncpg`` on first import and keeps that
    reference, so the stub always forwards through the module-level holder
    instead of a per-call closure.
    """

    class FakePool:
        async def close(self):
            return None

    async def create_pool(**kwargs):
        CAPTURED_POOL_KWARGS.clear()
        CAPTURED_POOL_KWARGS.update(kwargs)
        return FakePool()

    module = types.ModuleType("asyncpg")
    connection_module = types.ModuleType("asyncpg.connection")
    connection_module.Connection = object
    module.connection = connection_module
    module.create_pool = create_pool
    sys.modules["asyncpg"] = module
    return module


def test_repr_masks_password_for_both_backend_labels():
    plain = DatabaseURL(
        f"postgresql://{ENCODED_USERNAME}:{PASSWORD}@localhost:5432/appdb"
    )
    assert plain.scheme == "postgresql"
    assert plain.dialect == "postgresql"
    assert plain.driver == ""
    assert repr(plain) == (
        f"DatabaseURL('postgresql://{ENCODED_USERNAME}:********"
        "@localhost:5432/appdb')"
    )

    explicit_driver = DatabaseURL(ORIGINAL_URL)
    assert explicit_driver.scheme == "postgresql+asyncpg"
    assert explicit_driver.dialect == "postgresql"
    assert explicit_driver.driver == "asyncpg"
    assert repr(explicit_driver) == (
        f"DatabaseURL('postgresql+asyncpg://{ENCODED_USERNAME}:********"
        "@localhost:5432/appdb?ssl=true')"
    )

    for url in (plain, explicit_driver):
        assert PASSWORD not in repr(url)
        assert PASSWORD not in url.obscure_password


def test_encoded_password_is_masked_in_repr():
    url = DatabaseURL(
        f"postgresql+asyncpg://{ENCODED_USERNAME}:{ENCODED_PASSWORD}"
        "@localhost:5432/appdb"
    )

    assert url.password == "[password"
    assert ENCODED_PASSWORD in str(url)
    assert ENCODED_PASSWORD not in repr(url)
    assert "[password" not in repr(url)
    assert repr(url) == (
        f"DatabaseURL('postgresql+asyncpg://{ENCODED_USERNAME}:********"
        "@localhost:5432/appdb')"
    )


def test_encoded_username_is_preserved_and_decoded():
    url = DatabaseURL(ORIGINAL_URL)

    assert url.username == "user@example.com"
    assert ENCODED_USERNAME in repr(url)
    assert "user@example.com" not in repr(url)
    assert PASSWORD not in repr(url)


def test_copied_url_keeps_credentials_and_adjusts_options():
    original = DatabaseURL(ORIGINAL_URL)
    copied = DatabaseURL(original)

    assert copied == original
    assert copied.password == PASSWORD
    assert copied.username == "user@example.com"
    assert PASSWORD not in repr(copied)

    adjusted = copied.replace(
        query="ssl=true&min_size=1", database="appdb_replica"
    )

    assert adjusted.options == {"ssl": "true", "min_size": "1"}
    assert adjusted.database == "appdb_replica"
    assert adjusted.password == PASSWORD
    assert adjusted.username == "user@example.com"
    assert str(adjusted) == (
        f"postgresql+asyncpg://{ENCODED_USERNAME}:{PASSWORD}"
        "@localhost:5432/appdb_replica?ssl=true&min_size=1"
    )
    assert repr(adjusted) == (
        f"DatabaseURL('postgresql+asyncpg://{ENCODED_USERNAME}:********"
        "@localhost:5432/appdb_replica?ssl=true&min_size=1')"
    )
    assert PASSWORD not in repr(adjusted)


@async_adapter
async def test_driver_receives_real_credentials_but_repr_stays_masked():
    _install_stub_asyncpg()

    from databases.backends.postgres import PostgresBackend

    backend = PostgresBackend(ORIGINAL_URL)
    await backend.connect()
    try:
        assert CAPTURED_POOL_KWARGS == {
            "host": "localhost",
            "port": 5432,
            "user": "user@example.com",
            "password": PASSWORD,
            "database": "appdb",
            "ssl": True,
        }
    finally:
        await backend.disconnect()

    public_repr = repr(backend._database_url)
    assert CAPTURED_POOL_KWARGS["password"] == PASSWORD
    assert PASSWORD not in public_repr
    assert "********" in public_repr


@async_adapter
async def test_driver_receives_real_credentials_for_copied_url():
    _install_stub_asyncpg()

    from databases.backends.postgres import PostgresBackend

    copied = DatabaseURL(DatabaseURL(ORIGINAL_URL))
    backend = PostgresBackend(copied)
    await backend.connect()
    try:
        assert CAPTURED_POOL_KWARGS["user"] == "user@example.com"
        assert CAPTURED_POOL_KWARGS["password"] == PASSWORD
    finally:
        await backend.disconnect()

    assert PASSWORD not in repr(copied)
    assert PASSWORD not in repr(backend._database_url)


def test_copied_url_error_message_does_not_leak_raw_text():
    copied = DatabaseURL(DatabaseURL(ORIGINAL_URL))
    unsupported = copied.replace(scheme="bogus+unknown")

    with pytest.raises(KeyError) as exc_info:
        Database(unsupported)

    message = str(exc_info.value)
    assert PASSWORD not in message
    assert PASSWORD not in repr(exc_info.value)
    assert PASSWORD not in repr(unsupported)
    assert "********" in repr(unsupported)


def test_invalid_type_error_does_not_leak_credentials():
    with pytest.raises(TypeError) as exc_info:
        DatabaseURL(("postgresql", ENCODED_USERNAME, PASSWORD, "localhost", "appdb"))

    assert PASSWORD not in str(exc_info.value)
