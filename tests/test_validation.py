"""
Tests for opt-in connection validation.

These tests use fake backends so they can observe exactly which driver was
selected and whether a connection was opened, without contacting a real
network service.
"""

import asyncio
import typing

import pytest

from databases import (
    ConnectionValidationError,
    Database,
    DatabaseURL,
    RequireTLS,
    TLSConfigurationError,
    UnsupportedDriverError,
)
from databases.interfaces import DatabaseBackend

MODULE = __name__


class RecordingBackend(DatabaseBackend):
    driver = "fakedriver"
    supports_tls = True

    def __init__(
        self, database_url: typing.Union[DatabaseURL, str], **options: typing.Any
    ) -> None:
        self._database_url = DatabaseURL(database_url)
        self._options = options
        self.connected = False
        self.connect_calls = 0
        # What the driver would actually receive at connect time.
        self.received_options: typing.Dict[str, typing.Any] = {}

    async def connect(self) -> None:
        self.connect_calls += 1
        self.received_options = dict(self.connection_options())
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    def connection(self) -> typing.Any:
        raise NotImplementedError  # pragma: no cover


class PlainBackend(RecordingBackend):
    driver = "plaindriver"
    supports_tls = False


class FakeTLSBackend(RecordingBackend):
    driver = "tlsdriver"
    supports_tls = True


class BrokenOptionsBackend(FakeTLSBackend):
    driver = "broken"

    def connection_options(self):
        raise RuntimeError("cannot merge options")


@pytest.fixture(autouse=True)
def record_fake_backends(monkeypatch):
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake",
        f"{MODULE}:FakeTLSBackend",
    )
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+tlsdriver",
        f"{MODULE}:FakeTLSBackend",
    )
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+tls",
        f"{MODULE}:FakeTLSBackend",
    )
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+plaindriver",
        f"{MODULE}:PlainBackend",
    )
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+plain",
        f"{MODULE}:PlainBackend",
    )
    yield


async def _connect(database):
    await database.connect()
    await database.disconnect()


def run(coroutine):
    return asyncio.run(coroutine)


def test_valid_connection_is_opened_on_the_selected_driver(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=verify-full",
        validator=RequireTLS(),
    )
    assert database.driver == "tlsdriver"

    run(_connect(database))

    backend = database.backend
    assert backend.connect_calls == 1
    assert backend.connected is False  # disconnected again
    assert backend._options == {}


def test_valid_connection_accepts_matching_override(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=true",
        validator=RequireTLS(),
        ssl=True,
    )
    run(_connect(database))

    assert database.backend.connect_calls == 1


def test_conflicting_override_is_rejected_before_connect(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=verify-full",
        validator=RequireTLS(),
        ssl=False,
    )

    with pytest.raises(TLSConfigurationError) as exc_info:
        run(database.connect())

    error = exc_info.value
    assert error.driver == "tlsdriver"
    assert error.option == "ssl"
    assert "verify-full" in str(error)
    assert "False" in str(error)
    assert database.is_connected is False

    backend = database.backend
    assert backend.connect_calls == 0
    assert backend.connected is False


def test_conflicting_override_can_be_allowed(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=false",
        validator=RequireTLS(reject_overrides=False),
        ssl=True,
    )
    run(_connect(database))

    assert database.backend.connect_calls == 1


def test_unsupported_driver_is_rejected_before_connect(record_fake_backends):
    database = Database(
        "fake+plaindriver://localhost/database?ssl=require",
        validator=RequireTLS(),
    )

    with pytest.raises(UnsupportedDriverError) as exc_info:
        run(database.connect())

    assert exc_info.value.driver == "plaindriver"
    assert database.backend.connect_calls == 0
    assert database.is_connected is False


def test_driver_fallback_is_rejected_before_connect(record_fake_backends):
    # `fake+otherdriver` is not registered, so `_get_backend()` falls back to
    # the `fake` dialect's backend. Without the requested-driver check the
    # connection would silently be opened with `tlsdriver` instead.
    database = Database(
        "fake+otherdriver://localhost/database?ssl=verify-full",
        validator=RequireTLS(),
    )
    assert database.url.driver == "otherdriver"
    assert database.driver == "tlsdriver"

    with pytest.raises(UnsupportedDriverError) as exc_info:
        run(database.connect())

    assert "otherdriver" in str(exc_info.value)
    assert database.backend.connect_calls == 0


def test_missing_tls_setting_is_rejected(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database",
        validator=RequireTLS(),
    )

    with pytest.raises(TLSConfigurationError):
        run(database.connect())

    assert database.backend.connect_calls == 0


def test_unapproved_tls_mode_is_rejected(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=false",
        validator=RequireTLS(),
    )

    with pytest.raises(TLSConfigurationError):
        run(database.connect())

    assert database.backend.connect_calls == 0


def test_custom_validator_receives_effective_driver_and_options(
    record_fake_backends,
):
    seen = []

    def require_reviewed_transport(context):
        seen.append(context)
        if context.driver != "tlsdriver":
            raise UnsupportedDriverError("unexpected driver", driver=context.driver)
        if context.options.get("ssl") != "verify-full":
            raise TLSConfigurationError("unapproved mode", driver=context.driver)

    database = Database(
        "fake+tlsdriver://localhost/database?ssl=require",
        validator=[require_reviewed_transport],
        ssl="verify-full",
    )
    run(_connect(database))

    assert len(seen) == 1
    context = seen[0]
    assert context.driver == "tlsdriver"
    assert context.requested_driver == "tlsdriver"
    assert context.options["ssl"] == "verify-full"
    assert context.url_options["ssl"] == "require"
    assert context.application_options["ssl"] == "verify-full"
    assert database.backend.connect_calls == 1


def test_plain_sqlite_connection_does_not_run_tls_checks():
    async def scenario():
        database = Database("sqlite+aiosqlite:///:memory:")
        async with database:
            return await database.fetch_val("SELECT 1")

    assert run(scenario()) == 1


def test_sqlite_is_rejected_when_tls_is_required():
    database = Database("sqlite+aiosqlite:///:memory:", validator=RequireTLS())

    with pytest.raises(UnsupportedDriverError) as exc_info:
        run(database.connect())

    assert exc_info.value.driver == "aiosqlite"


def test_invalid_validator_type_is_rejected():
    with pytest.raises(TypeError):
        Database("sqlite+aiosqlite:///:memory:", validator="not-a-callable")

    with pytest.raises(TypeError):
        Database("sqlite+aiosqlite:///:memory:", validator=[object()])


def test_validator_runs_from_the_async_context_manager(record_fake_backends):
    async def scenario():
        async with Database(
            "fake+tlsdriver://localhost/database?ssl=true",
            validator=RequireTLS(),
        ) as database:
            return database.is_connected

    assert run(scenario()) is True

    # Connection was rejected while entering; nothing was opened.
    async def rejected():
        async with Database(
            "fake+plaindriver://localhost/database?ssl=true",
            validator=RequireTLS(),
        ):
            raise AssertionError("connection should not have been established")

    with pytest.raises(UnsupportedDriverError):
        run(rejected())


def test_no_validator_means_no_checks(record_fake_backends):
    # A backend that cannot do TLS is still usable when the deployment has not
    # opted into validation.
    database = Database("fake+plaindriver://localhost/database")
    run(_connect(database))
    assert database.backend.connect_calls == 1


def test_no_checks_on_reconnect_after_rejection(record_fake_backends):
    database = Database(
        "fake+plaindriver://localhost/database?ssl=true",
        validator=RequireTLS(),
    )
    with pytest.raises(UnsupportedDriverError):
        run(database.connect())

    # The failed validation must leave no connected backend behind, and a
    # second attempt must fail the same way rather than proceeding.
    assert database.is_connected is False
    with pytest.raises(UnsupportedDriverError):
        run(database.connect())
    assert database.backend.connect_calls == 0


def test_builtin_driver_resolution_is_visible_to_validators(monkeypatch):
    seen = []

    def capture(context):
        seen.append((context.driver, context.requested_driver, context.options))

    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+tls",
        f"{MODULE}:FakeTLSBackend",
    )
    # A bare dialect URL is resolved to the dialect's default backend; the
    # validator should see the concrete driver rather than an empty string.
    database = Database("fake://localhost/database?ssl=true", validator=capture)
    run(_connect(database))

    assert seen == [("tlsdriver", "", {"ssl": "true"})]


def test_allow_custom_tls_mapping(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database",
        validator=RequireTLS(allow_custom=True),
        ssl={"mode": "verify-full"},
    )
    run(_connect(database))

    assert database.backend.connect_calls == 1
    assert database.connection_options()["ssl"] == {"mode": "verify-full"}


def test_empty_mapping_is_treated_as_disabled(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database",
        validator=RequireTLS(),
        ssl={},
    )
    with pytest.raises(TLSConfigurationError):
        run(database.connect())
    assert database.backend.connect_calls == 0


def test_none_tls_setting_is_treated_as_disabled(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database",
        validator=RequireTLS(),
        ssl=None,
    )
    with pytest.raises(TLSConfigurationError):
        run(database.connect())
    assert database.backend.connect_calls == 0


def test_driver_enforcement_can_be_disabled(record_fake_backends):
    database = Database(
        "fake+otherdriver://localhost/database?ssl=verify-full",
        validator=RequireTLS(enforce_driver=False),
    )
    run(_connect(database))

    # The backend that actually opened the connection is recorded on the
    # database, so the fallback is observable rather than silent.
    assert database.driver == "tlsdriver"
    assert database.backend.connect_calls == 1


def test_empty_allowed_modes_is_rejected():
    with pytest.raises(ValueError):
        RequireTLS(allowed_modes=set())


def test_normalize_rejects_non_iterable_validator():
    with pytest.raises(TypeError):
        Database("sqlite+aiosqlite:///:memory:", validator=object())


def test_validate_connection_can_run_without_connecting(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=verify-full",
        validator=RequireTLS(),
    )
    database.validate_connection()
    assert database.is_connected is False
    assert database.backend.connect_calls == 0


def test_option_inspection_failure_is_a_validation_error(record_fake_backends):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake+broken",
        f"{MODULE}:BrokenOptionsBackend",
    )
    try:
        database = Database(
            "fake+broken://localhost/database?ssl=true", validator=RequireTLS()
        )
        with pytest.raises(ConnectionValidationError) as exc_info:
            run(database.connect())
        assert exc_info.value.driver == "broken"
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert database.backend.connect_calls == 0
    finally:
        monkeypatch.undo()


def test_validator_returning_false_rejects_connection(record_fake_backends):
    def deny(context):
        return False

    database = Database("fake+tlsdriver://localhost/database?ssl=true", validator=deny)
    with pytest.raises(ConnectionValidationError):
        run(database.connect())
    assert database.backend.connect_calls == 0


def test_driver_receives_the_effective_option_not_the_url_value(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=false",
        validator=RequireTLS(reject_overrides=False),
        ssl="verify-full",
    )
    run(_connect(database))

    # The application keyword argument wins; the driver must see that value,
    # and validation decided on that same effective configuration.
    assert database.backend.received_options == {"ssl": "verify-full"}


def test_url_only_conflicting_source_is_accepted_when_matching(record_fake_backends):
    database = Database(
        "fake+tlsdriver://localhost/database?ssl=TRUE",
        validator=RequireTLS(),
        ssl="require",
    )
    run(_connect(database))

    # Both sources describe the same mode even though the strings differ.
    assert database.backend.connect_calls == 1
    assert database.backend.received_options == {"ssl": "require"}


class LegacyTLSBackend(RecordingBackend):
    # No explicit capability declaration; the rule falls back to recognizing
    # the concrete driver name.
    driver = "asyncpg"
    supports_tls = None


def test_undeclared_capability_falls_back_to_known_driver(record_fake_backends):
    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(
            Database.SUPPORTED_BACKENDS,
            "legacy",
            f"{MODULE}:LegacyTLSBackend",
        )
        database = Database(
            "legacy://localhost/database?ssl=verify-full",
            validator=RequireTLS(),
        )
        database.validate_connection()
        run(_connect(database))

    assert database.backend.connect_calls == 1


def test_tls_mode_normalization_for_custom_values():
    from databases.validation import _tls_mode

    assert _tls_mode(None) == "disabled"
    assert _tls_mode(True) == "require"
    assert _tls_mode(False) == "disabled"
    assert _tls_mode(" TRUE ") == "require"
    assert _tls_mode("off") == "disabled"
    assert _tls_mode("prefer") == "prefer"
    assert _tls_mode({"mode": "verify-full"}) == "verify-full"
    assert _tls_mode({"cert": "client.pem"}) == "custom"
    assert _tls_mode(object()) == "custom"
