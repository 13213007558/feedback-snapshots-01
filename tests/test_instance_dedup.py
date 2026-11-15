from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.cim.cim import CIM
from dissect.cim.classes import InstanceIdentity, InstanceKey


@pytest.fixture
def repo(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> CIM:
    return CIM(index_bin, objects_bin, mappings_bin)


def test_enumeration_keeps_distinct_instances(repo: CIM) -> None:
    namespace = repo.root.namespace("CIMV2")
    instances = list(namespace.class_("__NAMESPACE").instances)

    assert len(instances) == 5
    identities = [instance.identity for instance in instances]
    assert len(set(identities)) == 5
    assert all(identity.namespace == "root\\cimv2" for identity in identities)
    assert all(identity.class_name == "__namespace" for identity in identities)


def test_text_lookup_matches_display_entry_point(repo: CIM) -> None:
    namespace = repo.root.namespace("CIMV2")
    class_ = namespace.class_("__NAMESPACE")
    instance = class_.instance("Name=mdm")

    assert str(instance.key) == "Name=mdm"
    assert class_.instance("Name=mdm").identity == instance.identity

    with pytest.raises(IndexError):
        class_.instance("Name=does-not-exist")


def test_structured_lookup_is_order_independent(repo: CIM) -> None:
    namespace = repo.root.namespace("CIMV2")
    class_ = namespace.class_("__NAMESPACE")
    instance = class_.instance({"Name": "mdm"})

    assert instance.identity == class_.instance(InstanceKey({"Name": "mdm"})).identity

    query_result = repo.query(r"root\CIMV2:__NAMESPACE.Name='mdm'")
    assert query_result.identity == instance.identity


def test_multi_key_instance_values_keep_semicolons_and_equals(repo: CIM) -> None:
    namespace = repo.root.namespace("subscription")
    binding = next(namespace.class_("__FilterToConsumerBinding").instances)

    assert "=" in binding.key["Consumer"]
    assert '"' in binding.key["Consumer"]
    assert binding.identity.components["Consumer"].endswith('"SCM Event Log Consumer"')

    # The display string still contains both key components while the identity stays
    # a single two-part structured key instead of splitting the embedded separators.
    assert str(binding.key).count(";") == 1
    assert set(binding.identity.components) == {"Consumer", "Filter"}
    assert len(binding.identity.components) == 2


def test_keyless_instance_uses_default_identity(repo: CIM) -> None:
    namespace = repo.root.namespace("WMI")
    instance = next(namespace.class_("MS_SM_HbaApiVersion").instances)

    assert dict(instance.key) == {}
    assert str(instance.key) == "default"
    assert instance.identity.is_default
    assert instance.identity.name == "default"
    assert instance.identity.explain() == "root\\wmi/ms_sm_hbaapiversion[default]"


def test_identity_does_not_merge_classes(repo: CIM) -> None:
    cimv2 = repo.root.namespace("CIMV2").class_("__NAMESPACE").instance({"Name": "ms_409"})
    default_ns = repo.root.namespace("DEFAULT").class_("__NAMESPACE").instance({"Name": "ms_409"})

    # The same key dictionary in two namespaces/classes must remain distinct objects.
    assert dict(cimv2.key) == dict(default_ns.key)
    assert cimv2.identity != default_ns.identity
    assert cimv2.identity.namespace != default_ns.identity.namespace


def test_dedup_report_explains_collapsed_references(repo: CIM) -> None:
    namespace = repo.root.namespace("subscription")
    class_ = namespace.class_("__FilterToConsumerBinding")

    groups = class_.instance_dedup_report()
    assert len(groups) == len(list(class_.instances))
    assert all(group.reference_count >= 1 for group in groups)
    assert all(group.duplicate_count == group.reference_count - 1 for group in groups)
    assert groups[0].identity.explain().startswith("root\\subscription/__filtertoconsumerbinding[")


@pytest.mark.slow
def test_enumeration_dedupes_many_references_by_structured_identity(repo: CIM) -> None:
    namespace = repo.root.namespace("WMI")
    class_ = namespace.class_("WDMClassesOfDriver")

    raw_references = repo.key().NS(namespace.name).CI(class_.name).IL().references()
    groups = class_.instance_dedup_report()
    instances = list(class_.instances)

    assert len(raw_references) > len(groups)
    assert len(instances) == len(groups) == 1588
    assert sum(group.reference_count for group in groups) == len(raw_references)

    typed = next(iter(groups)).identity
    assert "int" in typed.value_types.values()

    # Every group is internally consistent and distinct from the other groups.
    identities = [group.identity for group in groups]
    assert len(set(identities)) == len(identities)
    for group in groups:
        assert all(record.instance.identity == group.identity for record in group.records)


@pytest.mark.slow
def test_structured_identity_roundtrip_on_typed_multi_key_instance(repo: CIM) -> None:
    namespace = repo.root.namespace("WMI")
    class_ = namespace.class_("WDMClassesOfDriver")
    instance = next(class_.instances)

    reordered = dict(reversed(list(instance.key.items())))
    assert class_.instance(reordered).identity == instance.identity
    assert class_.instance(str(instance.key)).identity == instance.identity

    numeric_name = next(name for name, value in instance.key.items() if isinstance(value, int))
    broken = dict(instance.key)
    broken[numeric_name] = str(broken[numeric_name])

    with pytest.raises(IndexError):
        class_.instance(broken)


def test_synthetic_display_collisions_are_not_deduped() -> None:
    embedded = InstanceIdentity.from_key("root\\x", "Collide", InstanceKey({"k": '1;b="weird=value"'}))
    split = InstanceIdentity.from_key("root\\x", "Collide", InstanceKey({"k": "1", "b": '"weird=value"'}))

    assert str(embedded.key) == str(split.key)
    assert embedded != split
    assert len({embedded, split}) == 2
