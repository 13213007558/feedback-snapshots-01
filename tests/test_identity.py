from __future__ import annotations

import pytest

from dissect.cim.classes import InstanceIdentity, InstanceKey


def identity(namespace: str, class_name: str, **key_values: object) -> InstanceIdentity:
    return InstanceIdentity.from_key(namespace, class_name, InstanceKey(key_values))


def test_instance_key_keeps_legacy_display() -> None:
    assert str(InstanceKey()) == "default"
    assert str(InstanceKey({"Name": "Beep"})) == "Name=Beep"
    assert str(InstanceKey([("a", "1"), ("b", "2")])) == "a=1;b=2"

    key = InstanceKey()
    key.Name = "Beep"
    assert key.Name == "Beep"
    assert key["Name"] == "Beep"


def test_colliding_display_strings_are_distinct_instances() -> None:
    # A single value containing the key/value separators renders the same as two
    # separate key components, but the structural identities must stay distinct.
    embedded = identity("root\\x", "Collide", k="1;b=3")
    split = identity("root\\x", "Collide", k="1", b="3")

    assert str(embedded.key) == str(split.key) == "k=1;b=3"
    assert embedded != split
    assert len({embedded, split}) == 2
    assert embedded.components != split.components


def test_numeric_and_textual_values_are_distinct_even_when_display_matches() -> None:
    numeric = identity("root\\x", "Typed", k=1)
    textual = identity("root\\x", "Typed", k="1")

    assert str(numeric.key) == str(textual.key) == "k=1"
    assert numeric != textual
    assert len({numeric, textual}) == 2
    assert "int" in numeric.explain()
    assert "str" in textual.explain()


def test_key_order_does_not_change_identity() -> None:
    forward = InstanceIdentity.from_key("root\\x", "Ordered", InstanceKey([("a", "1"), ("b", "2")]))
    reversed_key = InstanceIdentity.from_key("ROOT\\X", "ORDERED", InstanceKey([("b", "2"), ("a", "1")]))

    assert forward == reversed_key
    assert hash(forward) == hash(reversed_key)
    assert len({forward, reversed_key}) == 1


def test_identity_is_bound_to_namespace_and_class() -> None:
    first = identity("root\\a", "Same", k="v")
    other_class = identity("root\\a", "Other", k="v")
    other_namespace = identity("root\\b", "Same", k="v")

    assert first != other_class
    assert first != other_namespace
    assert len({first, other_class, other_namespace}) == 3


def test_keyless_default_instances_collapse_only_within_one_class() -> None:
    first = InstanceIdentity.from_key("root\\x", "Singleton", InstanceKey())
    same = InstanceIdentity.from_key("root\\x", "Singleton", InstanceKey())
    other_class = InstanceIdentity.from_key("root\\x", "OtherSingleton", InstanceKey())

    assert first.name == "default"
    assert first.is_default
    assert first == same
    assert first != other_class
    assert first.explain() == "root\\x/singleton[default]"


def test_explain_is_order_independent_and_type_aware() -> None:
    forward = identity("root\\x", "Explain", a="1", b=2)
    reversed_key = InstanceIdentity.from_key("root\\x", "Explain", InstanceKey([("b", 2), ("a", "1")]))

    assert forward.explain() == reversed_key.explain()
    explained = forward.explain()
    assert "a:str='1'" in explained
    assert "b:int=2" in explained


def test_array_valued_keys_compare_element_wise() -> None:
    first = identity("root\\x", "Array", k=["a", "b"])
    same = identity("root\\x", "Array", k=["a", "b"])
    different = identity("root\\x", "Array", k=["a", "c"])

    assert first == same
    assert first != different


def test_identity_hash_uses_structured_tokens_not_display_string() -> None:
    first = identity("root\\x", "C", a="1", b="2")
    rebuilt = InstanceIdentity.from_key("root\\x", "C", {"b": "2", "a": "1"})

    assert rebuilt == first
    assert hash(rebuilt) == hash(first)

    # The display-only container stays a plain mutable dict and must not be mistaken
    # for a hashable identity.
    with pytest.raises(TypeError):
        hash(InstanceKey())
