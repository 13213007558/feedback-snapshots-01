from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.cim.cim import CIM
from dissect.cim.exceptions import (
    AmbiguousInstanceError,
    InstanceNotFoundError,
    InvalidInstancePathError,
    ObjectPathSyntaxError,
    UnsupportedHostError,
)
from dissect.cim.utils import ObjectPath, parse_object_path

if TYPE_CHECKING:
    from typing import BinaryIO


@pytest.fixture()
def repo(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> CIM:
    return CIM(index_bin, objects_bin, mappings_bin)


def test_cim(repo: CIM) -> None:
    assert repo

    subscription_ns = repo.root.namespace("subscription")
    binding = next(subscription_ns.class_("__filtertoconsumerbinding").instances)
    consumer = subscription_ns.query(binding.properties["Consumer"].value)
    assert consumer.properties["SourceName"].value == "Service Control Manager"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            'Win32_Service.Name="Beep"',
            ObjectPath("localhost", "root\\subscription", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            "Win32_Service.Name='Beep'",
            ObjectPath("localhost", "root\\subscription", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            'root\\cimv2:Win32_Service.Name="Beep"',
            ObjectPath("localhost", "root\\cimv2", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            '//./root/cimv2:Win32_Service.Name="Beep"',
            ObjectPath("localhost", "root\\cimv2", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            'winmgmts://./root/cimv2:Win32_Service.Name="Beep"',
            ObjectPath("localhost", "root\\cimv2", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            '//HOST/root/cimv2:Win32_Service.Name="Beep"',
            ObjectPath("HOST", "root\\cimv2", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            'Class.Name="a,b=c"',
            ObjectPath("localhost", "root\\subscription", "Class", {"Name": "a,b=c"}),
        ),
        (
            'Class.Name="a;b=c"',
            ObjectPath("localhost", "root\\subscription", "Class", {"Name": "a;b=c"}),
        ),
        (
            'Class.Name="a\\"b,c=d"',
            ObjectPath("localhost", "root\\subscription", "Class", {"Name": 'a"b,c=d'}),
        ),
        (
            'Class.Path="C:\\\\Windows\\\\system32"',
            ObjectPath("localhost", "root\\subscription", "Class", {"Path": "C:\\Windows\\system32"}),
        ),
        (
            'Class.A="x",B="y,z"',
            ObjectPath("localhost", "root\\subscription", "Class", {"A": "x", "B": "y,z"}),
        ),
    ],
)
def test_parse_object_path(repo: CIM, path: str, expected: ObjectPath) -> None:
    assert parse_object_path(path, repo.root.namespace("subscription")) == expected


@pytest.mark.parametrize(
    "path",
    [
        'Class.Name="unterminated',
        "Class.Name=",
        "Class.Name",
        'Class.Name="x",Name="y"',
        'Class.Name="x",',
        'Class.Name="unbalanced',
        "",
        "root\\cimv2:",
    ],
)
def test_parse_object_path_malformed(repo: CIM, path: str) -> None:
    with pytest.raises((ObjectPathSyntaxError, InvalidInstancePathError)):
        parse_object_path(path, repo.root.namespace("subscription"))


def test_query_binding_references(repo: CIM) -> None:
    subscription_ns = repo.root.namespace("subscription")
    binding = next(subscription_ns.class_("__FilterToConsumerBinding").instances)

    consumer_ref = binding.properties["Consumer"].value
    filter_ref = binding.properties["Filter"].value
    assert consumer_ref == 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'
    assert filter_ref == '__EventFilter.Name="SCM Event Log Filter"'

    consumer = repo.query(consumer_ref, subscription_ns)
    assert consumer.properties["Name"].value == "SCM Event Log Consumer"
    assert consumer.properties["SourceName"].value == "Service Control Manager"

    event_filter = repo.query(filter_ref, subscription_ns)
    assert event_filter.properties["Name"].value == "SCM Event Log Filter"

    instance = subscription_ns.class_("__FilterToConsumerBinding").instance(
        {"Consumer": consumer_ref, "Filter": filter_ref}
    )
    assert instance.properties["Consumer"].value == consumer_ref


def test_query_quoted_punctuation_is_exact(repo: CIM) -> None:
    subscription_ns = repo.root.namespace("subscription")
    consumer_class = subscription_ns.class_("NTEventLogEventConsumer")

    with pytest.raises(InstanceNotFoundError):
        consumer_class.instance({"Name": "SCM, Event=Log"})

    with pytest.raises(InstanceNotFoundError):
        consumer_class.instance({"Name": 'SCM Event Log Consumer"'})

    with pytest.raises(InstanceNotFoundError):
        consumer_class.instance({"Name": "scm event log consumer"})


def test_instance_not_found_is_not_enumeration(repo: CIM) -> None:
    with pytest.raises(InstanceNotFoundError) as exc_info:
        repo.query(
            'root\\subscription:NTEventLogEventConsumer.Name="no such, consumer=at all"',
        )
    assert "no such, consumer=at all" in str(exc_info.value)
    assert isinstance(exc_info.value, IndexError)


def test_remote_host_is_unsupported(repo: CIM) -> None:
    paths = (
        '//HOST/root/cimv2:Win32_Service.Name="Beep"',
        '\\\\HOST\\root\\cimv2:Win32_Service.Name="Beep"',
        'winmgmts://HOST/root/cimv2:Win32_Service.Name="Beep"',
    )
    for path in paths:
        parsed = parse_object_path(path)
        assert parsed.hostname == "HOST"

        with pytest.raises(UnsupportedHostError):
            repo.query(path)

    # A remote target stays unsupported even when the rest is malformed, and
    # must never fall through to a parse or a network lookup.
    for path in (
        '//HOST/root/cimv2:Win32_Service.Name="unterminated',
        "//HOST/root/cimv2:Win32_Service.Name=",
    ):
        with pytest.raises(UnsupportedHostError):
            repo.query(path)


def test_instance_key_ambiguous(repo: CIM, monkeypatch: pytest.MonkeyPatch) -> None:
    subscription_ns = repo.root.namespace("subscription")
    consumer_class = subscription_ns.class_("NTEventLogEventConsumer")

    instance = consumer_class.instance({"Name": "SCM Event Log Consumer"})
    monkeypatch.setattr(consumer_class, "_instances_for_key", lambda key: [instance, instance])

    with pytest.raises(AmbiguousInstanceError):
        consumer_class.instance({"Name": "SCM Event Log Consumer"})

def test_quoted_punctuation_consumers_are_distinct() -> None:
    # Two synthetic consumers that differ only by punctuation inside quotes.
    # This mirrors the acceptance case: same class and key name, but values that
    # a naive split on commas and equals signs would confuse.
    values = [
        'Consumer, primary="one"',
        "Consumer, primary='two'",
    ]

    paths = [f"root\\subscription:NTEventLogEventConsumer.Name={quote_key_value(value)}" for value in values]
    parsed = [parse_object_path(path) for path in paths]

    assert [path.instance for path in parsed] == [{"Name": value} for value in values]
    assert paths[0] != paths[1]
    assert parsed[0] != parsed[1]


def quote_key_value(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def test_quoted_punctuation_lookup_is_not_fuzzy(repo: CIM) -> None:
    subscription_ns = repo.root.namespace("subscription")
    consumer_class = subscription_ns.class_("NTEventLogEventConsumer")
    real = consumer_class.instance({"Name": "SCM Event Log Consumer"})

    values = [
        "SCM, Event=Log Consumer",
        'SCM Event Log Consumer"',
        "SCM Event Log Consumer;Name=other",
    ]
    for value in values:
        quoted = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        with pytest.raises(InstanceNotFoundError) as exc_info:
            repo.query(f"root\\subscription:NTEventLogEventConsumer.Name={quoted}")
        assert value in str(exc_info.value)

    assert real.properties["Name"].value == "SCM Event Log Consumer"


def test_instance_key_text_round_trips(repo: CIM) -> None:
    subscription_ns = repo.root.namespace("subscription")
    binding = next(subscription_ns.class_("__FilterToConsumerBinding").instances)

    text = str(binding.key)
    assert text == str(binding.class_instance.key)

    restored = subscription_ns.class_("__FilterToConsumerBinding").instance(text)
    assert restored.key == binding.key
    assert restored.properties["Consumer"].value == binding.properties["Consumer"].value


def test_malformed_reference_reports_syntax(repo: CIM) -> None:
    malformed = [
        'root\\subscription:NTEventLogEventConsumer.Name="SCM Event Log Consumer',
        "root\\subscription:NTEventLogEventConsumer.Name=",
        "root\\subscription:NTEventLogEventConsumer.Name",
        'root\\subscription:NTEventLogEventConsumer.Name="x",Name="y"',
        'root\\subscription:NTEventLogEventConsumer.Name="x"Trailing',
    ]

    for path in malformed:
        with pytest.raises(ObjectPathSyntaxError) as exc_info:
            repo.query(path)
        assert exc_info.value.path == path
        assert exc_info.value.position is not None
        assert "at position" in str(exc_info.value)


def test_binding_lookup_does_not_enumerate(repo: CIM, monkeypatch: pytest.MonkeyPatch) -> None:
    subscription_ns = repo.root.namespace("subscription")
    binding_class = subscription_ns.class_("__FilterToConsumerBinding")

    def fail_enumeration(*args: object, **kwargs: object) -> None:
        raise AssertionError("instance() must not enumerate all instances")

    monkeypatch.setattr(CIM, "get_class_instance", lambda *args, **kwargs: fail_enumeration())

    with pytest.raises(AssertionError):
        binding_class.instance(
            {
                "Consumer": 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"',
                "Filter": '__EventFilter.Name="SCM Event Log Filter"',
            }
        )
