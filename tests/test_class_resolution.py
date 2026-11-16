from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from dissect.cim.cim import CIM
from dissect.cim.exceptions import ClassNotFoundError, InvalidClassDefinitionError

if TYPE_CHECKING:
    from typing import BinaryIO

    from dissect.cim.cim import Class, Namespace


class FakeProperty:
    def __init__(self, name: str):
        self.name = name


class FakeClassDefinition:
    def __init__(self, name: str, super_class_name: str = "", properties: list[str] | None = None):
        self.class_name = name
        self.super_class_name = super_class_name
        self.properties = {name: FakeProperty(name) for name in properties or []}
        self.namespace: str | None = None

    def __repr__(self) -> str:
        return f"<FakeClassDefinition {self.class_name}>"


class BadDefinition:
    pass


class FakeKey:
    def __init__(self, cim: FakeCIM, namespace: str = "", class_name: str | None = None):
        self.cim = cim
        self.namespace = namespace
        self.class_name = class_name

    def __repr__(self) -> str:
        return f"<FakeKey {self.namespace}:{self.class_name}>"

    def NS(self, name: str | None = None) -> FakeKey:
        return FakeKey(self.cim, namespace=name or "", class_name=self.class_name)

    def CD(self, name: str | None = None) -> FakeKey:
        return FakeKey(self.cim, namespace=self.namespace, class_name=name if name is not None else self.class_name)

    def parts(self) -> dict[str, str]:
        return {"CD": self.class_name or ""}

    def references(self) -> list[FakeKey]:
        entries = self.cim.registry.get(self.namespace, {})
        if self.class_name is not None:
            return [FakeKey(self.cim, self.namespace, self.class_name)] if self.class_name in entries else []

        return [FakeKey(self.cim, self.namespace, name) for name in entries]

    @property
    def is_data_reference(self) -> bool:
        return False


class FakeCIM(CIM):
    def __init__(self, registry: dict[str, dict[str, FakeClassDefinition | BadDefinition]]):
        self.registry = registry

    def key(self) -> FakeKey:
        return FakeKey(self)

    def _class_reference(self, q: FakeKey) -> FakeKey | None:
        if q.class_name in self.registry.get(q.namespace, {}):
            return FakeKey(self, q.namespace, q.class_name)
        return None

    def _read_class_definition(self, q: FakeKey, namespace: str | None = None) -> FakeClassDefinition:
        entry = self.registry[q.namespace][q.class_name]  # type: ignore[index]
        if isinstance(entry, BadDefinition):
            raise InvalidClassDefinitionError(f"Invalid class definition: {q}")

        entry.namespace = q.namespace
        return entry


def make_cim() -> FakeCIM:
    return FakeCIM(
        {
            "root\\a": {
                "Shared": FakeClassDefinition("Shared", properties=["Local"]),
                "Base": FakeClassDefinition("Base", super_class_name="Shared", properties=["Base"]),
                "Derived": FakeClassDefinition("Derived", super_class_name="Base", properties=["Derived"]),
                "LocalOnly": FakeClassDefinition("LocalOnly", properties=["LocalOnly"]),
            },
            "root\\b": {
                "Shared": FakeClassDefinition("Shared", properties=["Other"]),
                "Derived": FakeClassDefinition("Derived", super_class_name="RemoteBase", properties=["OtherDerived"]),
            },
            "root\\broken": {
                "Broken": BadDefinition(),
            },
            "__SystemClass": {
                "Shared": FakeClassDefinition("Shared", properties=["System", "SystemOnly"]),
                "OnlySystem": FakeClassDefinition("OnlySystem", properties=["OnlySystem"]),
                "RemoteBase": FakeClassDefinition("RemoteBase", properties=["Remote"]),
                "Broken": FakeClassDefinition("Broken", properties=["SystemBroken"]),
            },
        }
    )


def snapshot(namespace: Namespace) -> list[tuple[str, str, str, tuple[str, ...]]]:
    return [
        (class_.name, class_.ns.name, class_.definition_source, tuple(class_.properties))
        for class_ in namespace.classes
    ]


def test_local_definition_wins_and_enumeration_is_stable() -> None:
    cim = make_cim()
    a = cim.namespace("root\\a")
    b = cim.namespace("root\\b")

    assert a.class_("Shared").definition_source == "root\\a"
    assert tuple(a.class_("Shared").properties) == ("Local",)

    assert b.class_("Shared").definition_source == "root\\b"
    assert tuple(b.class_("Shared").properties) == ("Other",)

    a_first = snapshot(a)
    b_first = snapshot(b)
    a_second = snapshot(a)
    b_second = snapshot(b)

    assert a_first == a_second
    assert b_first == b_second
    assert [entry for entry in a_first if entry[0] == "Shared"] == [("Shared", "root\\a", "root\\a", ("Local",))]
    assert [entry for entry in b_first if entry[0] == "Shared"] == [("Shared", "root\\b", "root\\b", ("Other",))]


def test_system_fallback_is_shared_without_mutating_namespace() -> None:
    cim = make_cim()
    a = cim.namespace("root\\a")
    b = cim.namespace("root\\b")

    a_system = a.class_("OnlySystem")
    assert a_system.ns.name == "root\\a"
    assert a_system.definition_source == "__SystemClass"
    assert a_system.is_system
    assert a_system.class_definition.namespace == "__SystemClass"

    b_system = b.class_("OnlySystem")
    assert b_system.ns.name == "root\\b"
    assert b_system.definition_source == "__SystemClass"
    assert b_system.is_system
    assert b_system.class_definition.namespace == "__SystemClass"

    # Looking the class up through another namespace must not change earlier objects.
    assert a.class_("OnlySystem").definition_source == "__SystemClass"
    assert a_system.ns.name == "root\\a"
    assert b_system.ns.name == "root\\b"


def test_system_fallback_does_not_override_missing_local_super_class() -> None:
    cim = make_cim()
    b = cim.namespace("root\\b")

    b_derived = b.class_("Derived")
    assert b_derived.ns.name == "root\\b"
    assert b_derived.definition_source == "root\\b"
    assert [(class_.name, class_.definition_source) for class_ in b_derived.derivation] == [
        ("RemoteBase", "__SystemClass"),
        ("Derived", "root\\b"),
    ]


def test_broken_local_definition_does_not_fall_back_to_system() -> None:
    cim = make_cim()
    broken = cim.namespace("root\\broken")

    with pytest.raises(InvalidClassDefinitionError):
        broken.class_("Broken")

    # The system namespace definitions remain independently readable.
    system_class = cim.namespace("__SystemClass").class_("Broken")
    assert system_class.definition_source == "__SystemClass"
    assert tuple(system_class.properties) == ("SystemBroken",)


def test_inheritance_uses_the_same_resolution_order() -> None:
    cim = make_cim()
    a = cim.namespace("root\\a")
    b = cim.namespace("root\\b")

    a_derived = a.class_("Derived")
    assert [(class_.name, class_.definition_source) for class_ in a_derived.derivation] == [
        ("Shared", "root\\a"),
        ("Base", "root\\a"),
        ("Derived", "root\\a"),
    ]
    assert tuple(a_derived.properties) == ("Local", "Base", "Derived")

    b_derived = b.class_("Derived")
    assert [(class_.name, class_.definition_source) for class_ in b_derived.derivation] == [
        ("RemoteBase", "__SystemClass"),
        ("Derived", "root\\b"),
    ]
    assert tuple(b_derived.properties) == ("Remote", "OtherDerived")

    property_sources = {name: prop.definition_source for name, prop in a_derived.properties.items()}
    assert property_sources == {"Local": "root\\a", "Base": "root\\a", "Derived": "root\\a"}

    property_sources = {name: prop.definition_source for name, prop in b_derived.properties.items()}
    assert property_sources == {"Remote": "__SystemClass", "OtherDerived": "root\\b"}


def test_missing_and_broken_definitions_are_different() -> None:
    cim = make_cim()
    a = cim.namespace("root\\a")
    broken = cim.namespace("root\\broken")

    with pytest.raises(ClassNotFoundError):
        a.class_("DoesNotExist")

    with pytest.raises(InvalidClassDefinitionError):
        broken.class_("Broken")

    with pytest.raises(InvalidClassDefinitionError):
        list(broken.classes)


def test_instance_query_after_interleaved_enumeration(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)
    subscription = cim.root.namespace("subscription")

    def query_consumer() -> tuple[Any, Any]:
        binding_class = subscription.class_("__FilterToConsumerBinding")
        binding = next(binding_class.instances)
        consumer = subscription.query(binding.properties["Consumer"].value)
        return binding_class, consumer

    first_class, first_consumer = query_consumer()
    list(cim.root.classes)
    list(cim.system.classes)
    list(subscription.classes)
    second_class, second_consumer = query_consumer()

    assert first_class.definition_source == "__SystemClass"
    assert second_class.definition_source == "__SystemClass"
    assert first_class.ns.name == "root\\subscription"
    assert second_class.ns.name == "root\\subscription"
    assert tuple(first_class.properties) == tuple(second_class.properties)
    assert first_consumer.properties["SourceName"].value == "Service Control Manager"
    assert second_consumer.properties["SourceName"].value == "Service Control Manager"
    assert second_consumer.key == first_consumer.key


def test_system_class_enumeration_keeps_system_namespace(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)

    system_classes = list(cim.system.classes)
    assert system_classes
    assert {class_.ns.name for class_ in system_classes} == {"__SystemClass"}
    assert {class_.definition_source for class_ in system_classes} == {"__SystemClass"}

    root_classes = list(cim.root.classes)
    assert {class_.ns.name for class_ in root_classes} == {"root"}
    assert any(not class_.is_system for class_ in root_classes)
    assert any(class_.is_system for class_ in root_classes)

    assert [class_.name for class_ in cim.system.classes] == [class_.name for class_ in system_classes]


def test_enumeration_and_lookup_agree(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)

    def layout(class_: Class) -> tuple[str, tuple[str, ...], tuple[int, ...]]:
        return (
            class_.definition_source,
            tuple(class_.properties),
            tuple(prop.index for prop in class_.properties.values()),
        )

    def snapshot(namespace: Namespace) -> dict[str, tuple[str, tuple[str, ...], tuple[int, ...]]]:
        return {class_.name: layout(class_) for class_ in namespace.classes}

    root = cim.root
    subscription = root.namespace("subscription")
    root_first = snapshot(root)
    subscription_first = snapshot(subscription)

    # Interleave enumeration and name lookup in both directions.
    for name, expected in root_first.items():
        assert layout(root.class_(name)) == expected
    for name, expected in subscription_first.items():
        assert layout(subscription.class_(name)) == expected

    assert snapshot(root) == root_first
    assert snapshot(subscription) == subscription_first
