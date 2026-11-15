from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.cim.cim import CIM
from dissect.cim.classes import InstanceIdentity, InstanceKey

NS = "root\\subscription"


def identity(key: dict, class_name: str = "Example", namespace: str = NS) -> InstanceIdentity:
    return InstanceIdentity(namespace, class_name, key)


def dedup_by_identity(identities: list[InstanceIdentity]) -> list[InstanceIdentity]:
    """Mirror of the deduplication logic in Class.instances."""
    yielded = set()
    result = []
    for ident in identities:
        if ident not in yielded:
            yielded.add(ident)
            result.append(ident)
    return result


def test_display_form_unchanged() -> None:
    assert str(InstanceKey()) == "default"
    assert str(InstanceKey({"A": 1, "B": "x"})) in ("A=1;B=x", "B=x;A=1")
    key = InstanceKey()
    key.Name = "Beep"
    assert key.Name == "Beep"
    assert str(key) == "Name=Beep"


def test_display_collision_numeric_vs_text() -> None:
    # Group 1: a numeric and a textual value render identically ("A=1")
    numeric = identity({"A": 1})
    textual = identity({"A": "1"})

    assert str(numeric.key) == str(textual.key) == "A=1"
    assert numeric != textual
    assert hash(numeric) != hash(textual)
    assert len(dedup_by_identity([numeric, textual])) == 2

    assert ":int" in numeric.describe()
    assert ":str" in textual.describe()


def test_display_collision_separators_in_values() -> None:
    # Group 2: a value containing ";" and "=" collides with a two-key display string
    single_key = identity({"A": "x;B=y"})
    two_keys = identity({"A": "x", "B": "y"})

    assert str(single_key.key) == str(two_keys.key) == "A=x;B=y"
    assert single_key != two_keys
    assert len(dedup_by_identity([single_key, two_keys])) == 2


def test_key_order_does_not_matter() -> None:
    # Group 3: references that only differ in key order are the same object
    forward = identity({"A": 1, "B": 2})
    backward = identity({"B": 2, "A": 1})

    assert str(forward.key) != str(backward.key)
    assert forward == backward
    assert hash(forward) == hash(backward)
    assert dedup_by_identity([forward, backward]) == [forward]


def test_identity_is_bound_to_namespace_and_class() -> None:
    key = {"Name": "Beep"}
    assert identity(key) == identity(key)
    assert identity(key, class_name="Other") != identity(key)
    assert identity(key, namespace="root\\cimv2") != identity(key)
    # namespace and class names compare case-insensitively, like the rest of CIM
    assert identity(key, namespace="ROOT\\SUBSCRIPTION") == identity(key)


def test_default_keyless_instances() -> None:
    assert str(InstanceKey()) == "default"

    default_a = identity({}, class_name="ClassA")
    default_a2 = identity({}, class_name="ClassA")
    default_b = identity({}, class_name="ClassB")

    # same display string ("default"), but identity is bound to the class
    assert str(default_a.key) == str(default_b.key) == "default"
    assert default_a == default_a2
    assert default_a != default_b
    assert len(dedup_by_identity([default_a, default_a2, default_b])) == 2
    assert "default keyless instance" in default_a.describe()


def test_parse_and_matches() -> None:
    key = InstanceKey.parse("A=1;B=hello")
    assert key == {"A": "1", "B": "hello"}
    assert InstanceKey.parse("default") == {}
    assert InstanceKey.parse("") == {}

    # quotes are only stripped when they wrap the whole value
    assert InstanceKey.parse('Name="Beep"') == {"Name": "Beep"}
    assert InstanceKey.parse('Ref=__EventFilter.Name="Beep"') == {"Ref": '__EventFilter.Name="Beep"'}

    # lookup is order-insensitive and tolerant of display-string values
    assert InstanceKey({"A": 1, "B": 2}).matches(InstanceKey.parse("B=2;A=1"))
    assert InstanceKey({"A": 1}).matches({"A": "1"})
    assert not InstanceKey({"A": 1}).matches({"A": 2})
    assert not InstanceKey({"A": 1}).matches({"A": 1, "B": 2})

    with pytest.raises(ValueError):
        InstanceKey.parse("not-a-key")


def test_real_enumeration_preserves_distinct_objects(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)
    subscription = cim.root.namespace("subscription")

    # this class has 5 instances sharing the same single key property
    registrations = list(subscription.class_("__EventConsumerProviderRegistration").instances)
    assert len(registrations) == 5
    assert len({instance.identity for instance in registrations}) == 5

    # keyless instances of different classes all display as "default" but stay distinct
    system_security = next(subscription.class_("__SystemSecurity").instances)
    this_namespace = next(subscription.class_("__thisNAMESPACE").instances)
    assert str(system_security.key) == str(this_namespace.key) == "default"
    assert system_security.identity != this_namespace.identity


def test_real_lookup_identifies_same_object(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)
    subscription = cim.root.namespace("subscription")
    binding_class = subscription.class_("__filtertoconsumerbinding")

    binding = next(binding_class.instances)
    assert set(binding.key) == {"Consumer", "Filter"}

    # a reference that only differs in key order
    reordered = dict(reversed(list(binding.key.items())))
    assert binding_class.instance(reordered).identity == binding.identity

    # lookup by identity and by the textual display form
    assert binding_class.instance(binding.identity).identity == binding.identity
    assert binding_class.instance(str(binding.key)).identity == binding.identity

    # a different key is not found
    with pytest.raises(IndexError):
        binding_class.instance({"Consumer": "nope", "Filter": "nope"})


def test_real_describe_explains_dedup_basis(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    cim = CIM(index_bin, objects_bin, mappings_bin)
    subscription = cim.root.namespace("subscription")
    binding = next(subscription.class_("__filtertoconsumerbinding").instances)

    description = binding.identity.describe()
    assert f"namespace={NS!r}" in description
    assert "class='__FilterToConsumerBinding'" in description
    assert "Consumer=" in description
    assert "Filter=" in description
