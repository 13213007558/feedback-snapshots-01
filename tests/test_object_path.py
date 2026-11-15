from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, BinaryIO, Any

import pytest

from dissect.cim.classes import InstanceKey
from dissect.cim.cim import CIM, Class, Instance
from dissect.cim.exceptions import InstanceNotFoundError, InvalidObjectPathError, UnsupportedHostError
from dissect.cim.utils import ObjectPath, parse_instance_keys, parse_object_path

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def cim(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> CIM:
    return CIM(index_bin, objects_bin, mappings_bin)


def _instance_with_key(
    base: Instance,
    namespace: Any,
    class_: Class,
    key: dict[str, Any],
    properties: dict[str, Any] | None = None,
) -> Instance:
    """Create an instance view that shares the real data but has a different key and/or property values."""
    base_properties = base.class_instance.properties
    if properties:
        base_properties = dict(base_properties)
        for name, value in properties.items():
            base_properties[name] = SimpleNamespace(value=value)

    class_instance = SimpleNamespace(key=InstanceKey(**key), properties=base_properties)
    return Instance(base.cim, namespace, class_, class_instance)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("Win32_Service", ObjectPath("localhost", None, "Win32_Service", {})),
        ("Win32_Service.Name='Beep'", ObjectPath("localhost", None, "Win32_Service", {"Name": "Beep"})),
        (
            'Win32_Service.Name="Beep",SystemCreationClassName="Win32_ComputerSystem"',
            ObjectPath(
                "localhost",
                None,
                "Win32_Service",
                {"Name": "Beep", "SystemCreationClassName": "Win32_ComputerSystem"},
            ),
        ),
        ("root/cimv2", ObjectPath("localhost", "root\\cimv2", "", {})),
        ("root\\cimv2", ObjectPath("localhost", "root\\cimv2", "", {})),
        ("//./root/cimv2", ObjectPath("localhost", "root\\cimv2", "", {})),
        ("//HOSTNAME/root/cimv2", ObjectPath("HOSTNAME", "root\\cimv2", "", {})),
        ("winmgmts://./root/cimv2", ObjectPath("localhost", "root\\cimv2", "", {})),
        ("//./root/cimv2:Win32_Service", ObjectPath("localhost", "root\\cimv2", "Win32_Service", {})),
        (
            '//./root/cimv2:Win32_Service.Name="Beep"',
            ObjectPath("localhost", "root\\cimv2", "Win32_Service", {"Name": "Beep"}),
        ),
        (
            '\\\\.\\root\\subscription:__EventFilter.Name="SCM Event Log Filter"',
            ObjectPath("localhost", "root\\subscription", "__EventFilter", {"Name": "SCM Event Log Filter"}),
        ),
        (
            'Class.Name="A,B=C",Other="x=y"',
            ObjectPath("localhost", None, "Class", {"Name": "A,B=C", "Other": "x=y"}),
        ),
        (
            'Class.Name="C:\\Windows\\System32"',
            ObjectPath("localhost", None, "Class", {"Name": "C:\\Windows\\System32"}),
        ),
        ('Class.Name="\\\\server\\share"', ObjectPath("localhost", None, "Class", {"Name": "\\\\server\\share"})),
        ("Class.Name='O''Brien'", ObjectPath("localhost", None, "Class", {"Name": "O'Brien"})),
        ('Class.Name="a""b"', ObjectPath("localhost", None, "Class", {"Name": 'a"b'})),
        ('Class.Name="a\\"b"', ObjectPath("localhost", None, "Class", {"Name": 'a"b'})),
        ('Class.Name="trailing\\"', ObjectPath("localhost", None, "Class", {"Name": "trailing\\"})),
        ("Class.Name=a:b", ObjectPath("localhost", None, "Class", {"Name": "a:b"})),
        ("Class.Name=1,Index=2", ObjectPath("localhost", None, "Class", {"Name": "1", "Index": "2"})),
    ],
)
def test_parse_object_path(path: str, expected: ObjectPath) -> None:
    assert parse_object_path(path) == expected


def test_parse_object_path_relative(cim: CIM) -> None:
    subscription = cim.namespace("root\\subscription")

    assert parse_object_path("ms_409", subscription) == ObjectPath("localhost", "root\\subscription\\ms_409", "", {})
    assert parse_object_path("__EventFilter", subscription) == ObjectPath(
        "localhost", "root\\subscription", "__EventFilter", {}
    )
    assert parse_object_path("root\\cimv2", subscription) == ObjectPath("localhost", "root\\cimv2", "", {})


@pytest.mark.parametrize(
    ("path", "position", "reason"),
    [
        ("", 0, "empty object path"),
        ('Class.Name="unterminated', 11, "unterminated quoted string"),
        ('Class.Name="a"b"', 14, "unexpected character after quoted value"),
        ("Class.Name=A,", 13, "empty instance key"),
        ("Class.Name", 10, "missing '=' after property name"),
        ("Class.Name=", 11, "missing value for property 'Name'"),
        ("Class..Name=1", 6, "invalid character in property name"),
        ("Class.Name=A,Name=B", 13, "duplicate property 'Name'"),
        ('Class.Name="A"garbage', 14, "unexpected character after quoted value"),
        ('Class.Name=A"B', 12, "unexpected quote in unquoted value"),
        ("Class.=A", 6, "missing property name"),
        ("root/cimv2:Name=A", 15, "instance path must separate the class and keys with a '.'"),
        ("//HOST", 2, "missing namespace path after host"),
        ("//.", 2, "missing namespace path after host"),
        ("//./", 4, "missing namespace path"),
        ("//", 2, "missing namespace path after host"),
        ("root/cimv2:", 11, "missing class name after namespace"),
    ],
)
def test_parse_object_path_invalid(path: str, position: int, reason: str) -> None:
    with pytest.raises(InvalidObjectPathError) as exc_info:
        parse_object_path(path)

    assert exc_info.value.position == position
    assert reason in exc_info.value.reason


def test_parse_object_path_relative_requires_namespace(cim: CIM) -> None:
    # Parsing a bare name as a class is allowed, but querying it without a namespace is not.
    assert parse_object_path("__EventFilter") == ObjectPath("localhost", None, "__EventFilter", {})

    with pytest.raises(InvalidObjectPathError):
        cim.query("__EventFilter")

    with pytest.raises(InvalidObjectPathError):
        cim.query('__Event"Filter')


def test_parse_instance_keys() -> None:
    assert parse_instance_keys('Name="A,B",Number=1') == {"Name": "A,B", "Number": "1"}
    assert parse_instance_keys('Name="C:\\Windows"') == {"Name": "C:\\Windows"}

    with pytest.raises(InvalidObjectPathError):
        parse_instance_keys("Name=A,")

    with pytest.raises(InvalidObjectPathError):
        parse_instance_keys("Name=A,Name=B")


def test_remote_host_is_rejected_without_network(cim: CIM) -> None:
    with pytest.raises(UnsupportedHostError) as exc_info:
        cim.query("//remote-host/root/cimv2:Win32_Service")

    assert exc_info.value.hostname == "remote-host"

    # A remote host must be rejected before the namespace or class is resolved.
    with pytest.raises(UnsupportedHostError):
        cim.query("//remote-host/does/not/exist:Nope")

    # Host names are not parsed as quoted values.
    with pytest.raises(InvalidObjectPathError):
        cim.query('//"remote-host"/root/cimv2')


def test_query_namespace_and_class(cim: CIM) -> None:
    namespace = cim.query("root/cimv2")
    assert namespace.name.lower() == "root\\cimv2"

    class_ = cim.query("//./root/cimv2:__Win32Provider")
    assert isinstance(class_, Class)
    assert class_.name == "__Win32Provider"


def test_query_consumer_references_with_punctuation(cim: CIM, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two consumers that differ only by punctuation inside the quoted key must resolve to different instances."""
    namespace = cim.namespace("root\\subscription")
    consumer_class = namespace.class_("NTEventLogEventConsumer")
    binding_class = namespace.class_("__FilterToConsumerBinding")

    names = ["Punctuation, Consumer", "Punctuation=Consumer"]
    references = [f'NTEventLogEventConsumer.Name="{name}"' for name in names]

    base = consumer_class.instance({"Name": "SCM Event Log Consumer"})
    consumers = [
        _instance_with_key(base, namespace, consumer_class, {"Name": name}) for name in names
    ]

    real_binding = next(binding_class.instances)
    bindings = [
        _instance_with_key(
            real_binding,
            namespace,
            binding_class,
            {"Consumer": reference, "Filter": real_binding.key["Filter"]},
            properties={"Consumer": reference},
        )
        for reference in references
    ]

    def instances(self: Class) -> Iterator[Instance]:
        if self.name == "NTEventLogEventConsumer":
            yield from consumers
        elif self.name == "__FilterToConsumerBinding":
            yield from bindings
        else:
            yield from original_instances(self)

    original_instances = Class.instances.fget
    monkeypatch.setattr(Class, "instances", property(instances))

    hits = []
    for binding in bindings:
        reference = binding.properties["Consumer"].value
        parsed = parse_object_path(reference, namespace)

        assert parsed.class_ == "NTEventLogEventConsumer"
        assert parsed.instance == {"Name": reference.split("=", 1)[1].strip('"')}

        hit = namespace.query(reference)
        assert isinstance(hit, Instance)
        hits.append(hit.key["Name"])

    assert hits == names
    assert hits[0] != hits[1]
def test_query_binding_consumer_reference(cim: CIM) -> None:
    namespace = cim.namespace("root\\subscription")
    binding = next(namespace.class_("__filtertoconsumerbinding").instances)
    reference = binding.properties["Consumer"].value

    parsed = parse_object_path(reference, namespace)
    assert parsed == ObjectPath(
        "localhost", "root\\subscription", "NTEventLogEventConsumer", {"Name": "SCM Event Log Consumer"}
    )

    consumer = namespace.query(reference)
    assert consumer.key["Name"] == "SCM Event Log Consumer"
    assert consumer.properties["SourceName"].value == "Service Control Manager"

    # The filter reference must not resolve to the consumer.
    filter_reference = binding.properties["Filter"].value
    assert parse_object_path(filter_reference, namespace).class_ == "__EventFilter"
    assert namespace.query(filter_reference).key["Name"] == "SCM Event Log Filter"


def test_query_provider_reference_with_backslashes(cim: CIM) -> None:
    namespace = cim.namespace("root\\default")
    reference = '\\\\.\\root\\default:__Win32Provider.Name="LogFileEventConsumer"'

    parsed = parse_object_path(reference, namespace)
    assert parsed.namespace == "root\\default"
    assert parsed.class_ == "__Win32Provider"
    assert parsed.instance == {"Name": "LogFileEventConsumer"}

    provider = cim.query(reference)
    assert provider.key["Name"] == "LogFileEventConsumer"


def test_instance_requires_complete_key(cim: CIM) -> None:
    class_ = cim.namespace("root\\subscription").class_("NTEventLogEventConsumer")

    with pytest.raises(InstanceNotFoundError):
        class_.instance({"Name": "SCM Event Log Consumer", "Extra": "value"})

    with pytest.raises(InstanceNotFoundError):
        class_.instance({"Bogus": "SCM Event Log Consumer"})

    with pytest.raises(InvalidObjectPathError):
        class_.instance('Name="SCM Event Log Consumer",')


def test_class_instance_does_not_fall_back_to_first_match(cim: CIM) -> None:
    class_ = cim.namespace("root\\subscription").class_("NTEventLogEventConsumer")

    with pytest.raises(InstanceNotFoundError):
        class_.instance({"Name": "SCM Event Log Consumer,"})

    with pytest.raises(InstanceNotFoundError):
        class_.instance('Name="SCM Event Log Consumer, "')


def test_query_multi_key_instance_with_windows_path(cim: CIM) -> None:
    """A composite key with a Windows path must match exactly and preserve backslashes."""
    namespace = cim.namespace("root\\wmi")
    class_ = namespace.class_("WMIBinaryMofResource")

    assert class_.keys == ["HighDateTime", "LowDateTime", "Name"]

    reference = (
        "WMIBinaryMofResource."
        "HighDateTime=30890515,"
        "LowDateTime=3169922776,"
        'Name="C:\\Windows\\System32\\drivers\\mssmbios.sys[MofResource]"'
    )

    parsed = parse_object_path(reference, namespace)
    assert parsed.instance == {
        "HighDateTime": "30890515",
        "LowDateTime": "3169922776",
        "Name": "C:\\Windows\\System32\\drivers\\mssmbios.sys[MofResource]",
    }

    hit = namespace.query(reference)
    assert hit.key["Name"] == "C:\\Windows\\System32\\drivers\\mssmbios.sys[MofResource]"
    assert hit.key["HighDateTime"] == 30890515

    # A wrong key value must not silently match a neighbouring instance.
    with pytest.raises(InstanceNotFoundError):
        namespace.query(reference.replace("30890515", "30890516"))


def test_instance_identity_with_separators_in_values(cim: CIM, monkeypatch: pytest.MonkeyPatch) -> None:
    """Distinct composite keys must not collapse just because a value contains the textual key separator."""
    namespace = cim.namespace("root\\subscription")
    class_ = namespace.class_("NTEventLogEventConsumer")
    base = class_.instance({"Name": "SCM Event Log Consumer"})

    # Both keys render identically as "Name=a;Other=b;Other=c" under the old string-based identity.
    first = {"Name": "a;Other=b", "Other": "c"}
    second = {"Name": "a", "Other": "b;Other=c"}

    original_instances = Class.instances.fget

    def instances(self: Class) -> Iterator[Instance]:
        if self.name == "NTEventLogEventConsumer":
            yield _instance_with_key(base, namespace, class_, first)
            yield _instance_with_key(base, namespace, class_, second)
        else:
            yield from original_instances(self)

    monkeypatch.setattr(Class, "instances", property(instances))

    keys = [dict(instance.key) for instance in class_.instances]
    assert keys == [first, second]
