"""Tests for the side-effect-free JSON separator probe."""

import pytest

from taskiq.formatters._wire_signature import json_separator_style
from taskiq.formatters.json_formatter import JSONFormatter
from taskiq.formatters.proxy_formatter import ProxyFormatter
from taskiq.brokers.inmemory_broker import InMemoryBroker
from taskiq.message import TaskiqMessage


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'{"a":1,"b":[2,3]}', False),
        (b'{"a": 1, "b": [2, 3]}', True),
        (b'{"a":"x, y: z"}', False),
        (b'{"a": "x, y: z"}', True),
        (b'{"a":"\\"{,}\\""}', False),
    ],
)
def test_separator_style(payload: bytes, expected: bool) -> None:
    assert json_separator_style(payload) is expected


@pytest.mark.parametrize("payload", [b"[]", b"null", b'"text"', b"", b"not json"])
def test_non_object_is_unknown(payload: bytes) -> None:
    assert json_separator_style(payload) is None


def test_truncated_object_is_unknown() -> None:
    assert json_separator_style(b'{"a": 1') is None


def test_builtin_formatters_disagree_on_their_own_output() -> None:
    broker = InMemoryBroker()
    proxy = ProxyFormatter(broker)
    upgraded = JSONFormatter()
    message = TaskiqMessage(
        task_id="id",
        task_name="task",
        labels={},
        args=[1, "value, with comma"],
        kwargs={"key": "a: b"},
    )

    proxy_payload = proxy.dumps(message).message
    json_payload = upgraded.dumps(message).message

    assert proxy.matches(proxy_payload) is True
    assert proxy.matches(json_payload) is False
    assert upgraded.matches(json_payload) is True
    assert upgraded.matches(proxy_payload) is False


def test_non_json_serializer_has_no_opinion() -> None:
    from taskiq.abc.serializer import TaskiqSerializer

    class RawSerializer(TaskiqSerializer):
        def dumpb(self, value: object) -> bytes:
            return repr(value).encode()

        def loadb(self, value: bytes) -> object:
            return eval(value)  # noqa: S307

    broker = InMemoryBroker().with_serializer(RawSerializer())
    assert ProxyFormatter(broker).matches(b"anything") is None
