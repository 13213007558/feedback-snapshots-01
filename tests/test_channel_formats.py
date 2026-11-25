"""Validation for channel-bound format policies."""

import pytest

from taskiq import ChannelFormat, ChannelFormatPolicy
from taskiq.brokers.inmemory_broker import InMemoryBroker
from taskiq.formatters.json_formatter import JSONFormatter
from taskiq.formatters.proxy_formatter import ProxyFormatter


def _proxy() -> ProxyFormatter:
    return ProxyFormatter(InMemoryBroker())


def test_default_version_comes_from_formatter() -> None:
    assert ChannelFormat(JSONFormatter()).version == "json"
    assert ChannelFormat(_proxy()).version == "proxy"


def test_explicit_version_wins() -> None:
    assert ChannelFormat(JSONFormatter(), version="v2").version == "v2"


def test_empty_version_falls_back() -> None:
    assert ChannelFormat(JSONFormatter(), version="").version == "json"


def test_legacy_defaults_to_false() -> None:
    assert ChannelFormat(JSONFormatter()).legacy is False


def test_formatter_must_be_a_formatter() -> None:
    with pytest.raises(ValueError, match="TaskiqFormatter"):
        ChannelFormat("json")  # type: ignore[arg-type]


def test_policy_requires_a_format_per_channel() -> None:
    with pytest.raises(ValueError, match="at least one format"):
        ChannelFormatPolicy(channels={"tasks": ()})


def test_policy_rejects_duplicate_versions() -> None:
    with pytest.raises(ValueError, match="duplicate format versions"):
        ChannelFormatPolicy(
            channels={
                "tasks": (
                    ChannelFormat(JSONFormatter(), version="v1"),
                    ChannelFormat(JSONFormatter(), version="v1"),
                ),
            },
        )


def test_policy_rejects_unknown_default_channel() -> None:
    with pytest.raises(ValueError, match="Default channel"):
        ChannelFormatPolicy(
            channels={"tasks": (ChannelFormat(JSONFormatter()),)},
            default_channel="missing",
        )


def test_policy_is_immutable() -> None:
    policy = ChannelFormatPolicy(
        channels={"tasks": (ChannelFormat(JSONFormatter()),)},
    )
    with pytest.raises(TypeError):
        policy.channels["tasks"] = ()  # type: ignore[index]


def test_policy_resolves_and_reports_versions() -> None:
    policy = ChannelFormatPolicy(
        channels={
            "legacy": (ChannelFormat(_proxy(), legacy=True),),
            "upgraded": (ChannelFormat(JSONFormatter()),),
        },
        default_channel="upgraded",
    )

    assert policy.resolve_channel(None) == "upgraded"
    assert policy.resolve_channel("legacy") == "legacy"
    assert policy.resolve_channel("other") is None
    assert policy.versions_for(None) == ("json",)
    assert policy.versions_for("legacy") == ("proxy",)
    assert policy.versions_for("other") == ()


def test_with_channel_returns_a_new_policy() -> None:
    policy = ChannelFormatPolicy(
        channels={"tasks": (ChannelFormat(JSONFormatter()),)},
        default_channel="tasks",
    )

    updated = policy.with_channel("tasks", ChannelFormat(JSONFormatter(), "v2"))

    assert policy.versions_for("tasks") == ("json",)
    assert updated.versions_for("tasks") == ("v2",)
    assert updated is not policy


def test_without_channel_returns_a_new_policy() -> None:
    policy = ChannelFormatPolicy(
        channels={
            "legacy": (ChannelFormat(_proxy()),),
            "upgraded": (ChannelFormat(JSONFormatter()),),
        },
        default_channel="upgraded",
    )

    updated = policy.without_channel("legacy")

    assert updated.versions_for("legacy") == ()
    assert updated.versions_for("upgraded") == ("json",)


def test_without_default_channel_raises() -> None:
    policy = ChannelFormatPolicy(
        channels={"upgraded": (ChannelFormat(JSONFormatter()),)},
        default_channel="upgraded",
    )

    with pytest.raises(ValueError, match="default channel"):
        policy.without_channel("upgraded")
