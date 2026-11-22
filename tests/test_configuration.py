from __future__ import annotations

import math
import threading
import time

import hiro
import pytest
from flask import Flask
from limits.errors import ConfigurationError
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter

from flask_limiter import ApplicationLimit, Limit, Limiter
from flask_limiter.constants import ConfigVars, HeaderNames
from flask_limiter.util import get_remote_address


def test_invalid_strategy():
    app = Flask(__name__)
    app.config.setdefault(ConfigVars.STRATEGY, "fubar")
    with pytest.raises(ConfigurationError):
        Limiter(get_remote_address, app=app)


def test_invalid_storage_string():
    app = Flask(__name__)
    app.config.setdefault(ConfigVars.STORAGE_URI, "fubar://localhost:1234")
    with pytest.raises(ConfigurationError):
        Limiter(get_remote_address, app=app)


def test_constructor_arguments_over_config(redis_connection):
    app = Flask(__name__)
    app.config.setdefault(ConfigVars.STRATEGY, "sliding-window-counter")
    limiter = Limiter(get_remote_address, strategy="moving-window")
    limiter.init_app(app)
    app.config.setdefault(ConfigVars.STORAGE_URI, "redis://localhost:46379")
    app.config.setdefault(ConfigVars.APPLICATION_LIMITS, "1/minute")
    app.config.setdefault(ConfigVars.META_LIMITS, "1/hour")
    assert type(limiter._limiter) is MovingWindowRateLimiter
    limiter = Limiter(get_remote_address, storage_uri="memory://")
    limiter.init_app(app)
    assert type(limiter._storage) is MemoryStorage

    @app.route("/")
    def root():
        return "root"

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 429
            timeline.forward(60)
            assert cli.get("/").status_code == 429


def test_header_names_config():
    app = Flask(__name__)
    app.config.setdefault(ConfigVars.HEADER_LIMIT, "XX-Limit")
    app.config.setdefault(ConfigVars.HEADER_REMAINING, "XX-Remaining")
    app.config.setdefault(ConfigVars.HEADER_RESET, "XX-Reset")
    limiter = Limiter(get_remote_address, headers_enabled=True, default_limits=["1/second"])
    limiter.init_app(app)

    @app.route("/")
    def root():
        return "42"

    with app.test_client() as client:
        resp = client.get("/")
        assert resp.headers["XX-Limit"] == "1"
        assert resp.headers["XX-Remaining"] == "0"
        assert resp.headers["XX-Reset"] == str(math.ceil(time.time() + 1))


def test_header_names_constructor():
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        headers_enabled=True,
        default_limits=["1/second"],
        header_name_mapping={
            HeaderNames.LIMIT: "XX-Limit",
            HeaderNames.REMAINING: "XX-Remaining",
            HeaderNames.RESET: "XX-Reset",
        },
    )
    limiter.init_app(app)

    @app.route("/")
    def root():
        return "42"

    with app.test_client() as client:
        resp = client.get("/")
        assert resp.headers["XX-Limit"] == "1"
        assert resp.headers["XX-Remaining"] == "0"
        assert resp.headers["XX-Reset"] == str(math.ceil(time.time() + 1))


def test_invalid_config_with_disabled():
    app = Flask(__name__)
    app.config.setdefault(ConfigVars.ENABLED, False)
    app.config.setdefault(ConfigVars.STORAGE_URI, "fubar://")

    limiter = Limiter(get_remote_address, app=app, default_limits=["1/hour"])

    @app.route("/")
    def root():
        return "root"

    @app.route("/explicit")
    @limiter.limit("2/hour")
    def explicit():
        return "explicit"

    with app.test_client() as client:
        assert client.get("/").status_code == 200
        assert client.get("/").status_code == 200
        assert client.get("/explicit").status_code == 200
        assert client.get("/explicit").status_code == 200
        assert client.get("/explicit").status_code == 200


def test_uninitialized_limiter():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, default_limits=["1/hour"])

    @app.route("/")
    @limiter.limit("2/hour")
    def root():
        return "root"

    with app.test_client() as client:
        assert client.get("/").status_code == 200
        assert client.get("/").status_code == 200
        assert client.get("/").status_code == 200


class CountingStorage(MemoryStorage):
    """In-memory storage that records every write attempt."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.writes = []

    def incr(self, key, expiry, amount=1):
        self.writes.append(("incr", key, amount))
        return super().incr(key, expiry, amount)

    def decr(self, key, amount=1):
        self.writes.append(("decr", key, amount))
        return super().decr(key, amount)


def _runtime_limit_values(limiter):
    return [str(limit.limit) for limit in limiter.limit_manager.default_limits], [
        str(limit.limit) for limit in limiter.limit_manager.application_limits
    ]


def _console_app():
    """
    A tiny application that mimics the new console: it publishes several
    default limits and one application wide limit through a single call.
    """
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        headers_enabled=True,
        default_limits=["10/day"],
        application_limits=["100/day"],
    )

    @app.route("/")
    def root():
        return "root"

    return app, limiter


def test_update_limits_switches_complete_configuration():
    app, limiter = _console_app()
    storage = CountingStorage()
    limiter._storage = storage
    limiter._limiter = type(limiter._limiter)(storage)

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            # before the switch: the original limits are in effect
            for _ in range(3):
                assert cli.get("/").status_code == 200
            assert _runtime_limit_values(limiter) == (["10 per 1 day"], ["100 per 1 day"])
            storage.writes.clear()

            # publish a complete set: multiple defaults + one application limit
            limiter.update_limits(
                default_limits=["2/minute", "5/hour"],
                application_limits=["3/minute"],
            )

            # the switch itself never writes to the storage
            assert storage.writes == []
            assert _runtime_limit_values(limiter) == (
                ["2 per 1 minute", "5 per 1 hour"],
                ["3 per 1 minute"],
            )

            # every request from now on is evaluated against the new set;
            # the previous hits in the old windows are not carried over
            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 200
            response = cli.get("/")
            assert response.status_code == 429
            # the smallest new default limit (2/minute) is what refused the
            # request, proving the whole published set is in effect
            assert response.headers["X-RateLimit-Limit"] == "2"
            assert "2 per 1 minute" in response.data.decode()

            # once the minute windows roll over the new configuration keeps
            # enforcing both groups
            timeline.forward(60)
            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 429


def test_update_limits_is_all_or_nothing_on_invalid_limit():
    app, limiter = _console_app()
    storage = CountingStorage()
    limiter._storage = storage
    limiter._limiter = type(limiter._limiter)(storage)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/").status_code == 200
            original_defaults, original_application = _runtime_limit_values(limiter)
            snapshot = dict(storage.storage)
            storage.writes.clear()

            # the second default limit is invalid: nothing may be applied
            with pytest.raises(ConfigurationError):
                limiter.update_limits(
                    default_limits=["2/minute", "not-a-limit"],
                    application_limits=["1/minute"],
                )

            # no partial update and no storage write happened
            assert storage.writes == []
            assert dict(storage.storage) == snapshot
            assert _runtime_limit_values(limiter) == (
                original_defaults,
                original_application,
            )

            # The old configuration (10/day) still decides requests: neither
            # the would-be 2/minute default nor the 1/minute application limit
            # leaked into the active configuration.
            current = _runtime_limit_values(limiter)
            assert "2 per 1 minute" not in current[0]
            assert "1 per 1 minute" not in current[1]

            for _ in range(8):
                assert cli.get("/").status_code == 200
            # 9 requests total today: the old 10/day default is one away
            assert cli.get("/").status_code == 200
            response = cli.get("/")
            assert response.status_code == 429
            assert "10 per 1 day" in response.data.decode()


def test_update_limits_validates_application_limits_too():
    app, limiter = _console_app()
    storage = CountingStorage()
    limiter._storage = storage
    limiter._limiter = type(limiter._limiter)(storage)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/").status_code == 200
            original_defaults, original_application = _runtime_limit_values(limiter)
            storage.writes.clear()

            # the defaults are valid but the application limit is not
            with pytest.raises(ConfigurationError):
                limiter.update_limits(
                    default_limits=["2/minute"],
                    application_limits=["3/fortnight"],
                )

            assert storage.writes == []
            assert _runtime_limit_values(limiter) == (
                original_defaults,
                original_application,
            )

            # the old configuration still decides requests
            assert cli.get("/").status_code == 200


def test_update_limits_accepts_limit_objects_and_keeps_unset_group():
    app, limiter = _console_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/").status_code == 200
            _, original_application = _runtime_limit_values(limiter)

            limiter.update_limits(
                default_limits=[Limit("1/minute"), "2/hour"],
            )

            defaults, application = _runtime_limit_values(limiter)
            assert defaults == ["1 per 1 minute", "2 per 1 hour"]
            # the application limits were left untouched
            assert application == original_application

            limiter.update_limits(application_limits=[ApplicationLimit("1/minute")])
            defaults, application = _runtime_limit_values(limiter)
            assert defaults == ["1 per 1 minute", "2 per 1 hour"]
            assert application == ["1 per 1 minute"]


def test_update_limits_dynamic_defaults_keep_per_request_evaluation():
    app = Flask(__name__)
    app.config["API_DEFAULT"] = "2/minute"
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        default_limits=["10/day"],
    )

    def dynamic_default():
        return app.config["API_DEFAULT"]

    @app.route("/")
    def root():
        return "root"

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert cli.get("/").status_code == 200
            assert _runtime_limit_values(limiter)[0] == ["10 per 1 day"]

            limiter.update_limits(
                default_limits=[dynamic_default, "5/hour"],
                application_limits=["50/hour"],
            )

            # dynamic defaults stay dynamic: they are not resolved at update time
            default_groups = limiter.limit_manager._default_limits
            assert default_groups[0].limit_provider is dynamic_default
            assert [str(limit.limit) for limit in default_groups[0]] == ["2 per 1 minute"]
            assert [str(limit.limit) for group in default_groups[1:] for limit in group] == [
                "5 per 1 hour"
            ]

            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 200
            response = cli.get("/")
            assert response.status_code == 429
            assert "2 per 1 minute" in response.data.decode()

            # changing what the callable returns is still honored per request
            app.config["API_DEFAULT"] = "1/minute"
            timeline.forward(60)
            assert cli.get("/").status_code == 200
            assert cli.get("/").status_code == 429


def test_update_limits_requires_initialized_limiter():
    limiter = Limiter(get_remote_address, default_limits=["1/minute"])

    with pytest.raises(ConfigurationError):
        limiter.update_limits(default_limits=["2/minute"])


def test_update_limits_reads_never_see_a_half_applied_configuration():
    app, limiter = _console_app()
    manager = limiter.limit_manager

    generations = [
        (["1/minute"], ["1/hour"]),
        (["2/minute", "3/hour"], ["2/hour"]),
        (["4/minute", "5/hour", "6/day"], ["3/hour"]),
    ]
    reader_stop = threading.Event()
    observed = []
    failures = []

    def reader():
        while not reader_stop.is_set():
            application_groups, default_groups = manager.snapshot_limit_groups()
            application_amounts = [
                limit.limit.amount for group in application_groups for limit in group
            ]
            default_amounts = [limit.limit.amount for group in default_groups for limit in group]
            observed.append((tuple(application_amounts), tuple(default_amounts)))

    def writer():
        try:
            for defaults, application in generations:
                limiter.update_limits(default_limits=defaults, application_limits=application)
        except Exception as err:  # pragma: no cover
            failures.append(err)

    reader_thread = threading.Thread(target=reader)
    writer_thread = threading.Thread(target=writer)
    reader_thread.start()
    writer_thread.start()
    writer_thread.join()
    reader_stop.set()
    reader_thread.join()

    assert not failures
    # every snapshot must be exactly one of the published generations
    initial = (["10/day"], ["100/day"])
    expected = {
        (
            tuple(int(limit.split("/")[0]) for limit in application),
            tuple(int(limit.split("/")[0]) for limit in defaults),
        )
        for defaults, application in [initial, *generations]
    }
    assert observed
    assert set(observed) <= expected
