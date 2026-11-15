from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.cim.cim import CIM
from dissect.cim.subscriptions import (
    EvidenceObject,
    LinkStatus,
    build_object_path,
    correlate_subscriptions,
    enumerate_subscriptions,
    parse_reference,
)

SUBSCRIPTION_NS = "root\\subscription"
OTHER_NS = "root\\evil"


def make_evidence(
    kind: str,
    namespace: str,
    class_name: str,
    key: dict[str, str],
    properties: dict[str, object] | None = None,
) -> EvidenceObject:
    properties = dict(key, **(properties or {}))
    return EvidenceObject(
        kind=kind,
        namespace=namespace,
        class_name=class_name,
        key=dict(key),
        properties=properties,
        object_path=build_object_path(namespace, class_name, key),
        source=f"fixture:{namespace}:{class_name}",
    )


def make_filter(namespace: str, name: str, query: str = "SELECT * FROM __InstanceModificationEvent") -> EvidenceObject:
    return make_evidence(
        "filter",
        namespace,
        "__EventFilter",
        {"Name": name},
        {
            "Name": name,
            "Query": query,
            "QueryLanguage": "WQL",
            "EventNamespace": "root\\cimv2",
        },
    )


def make_script_consumer(namespace: str, name: str, script: str) -> EvidenceObject:
    return make_evidence(
        "consumer",
        namespace,
        "ActiveScriptEventConsumer",
        {"Name": name},
        {
            "Name": name,
            "ScriptingEngine": "VBScript",
            "ScriptText": script,
        },
    )


def make_binding(namespace: str, filter_ref: str, consumer_ref: str) -> EvidenceObject:
    return make_evidence(
        "binding",
        namespace,
        "__FilterToConsumerBinding",
        {"Filter": filter_ref, "Consumer": consumer_ref},
        {"Filter": filter_ref, "Consumer": consumer_ref, "DeliverSynchronously": False},
    )


def test_enumerate_sample_repository_finds_complete_chain(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    report = enumerate_subscriptions(CIM(index_bin, objects_bin, mappings_bin))

    assert len(report.chains) == 1
    chain = report.chains[0]
    assert chain.is_complete
    assert chain.status is LinkStatus.COMPLETE
    assert chain.issues == ()

    assert chain.filter is not None
    assert chain.filter.namespace == SUBSCRIPTION_NS
    assert chain.filter.properties["Query"] == "select * from MSFT_SCMEventLogEvent"
    assert chain.filter.properties["QueryLanguage"] == "WQL"
    assert chain.filter.properties["EventNamespace"] == "root\\cimv2"

    assert chain.consumer is not None
    assert chain.consumer.class_name == "NTEventLogEventConsumer"
    assert chain.consumer.payload_properties["SourceName"] == "Service Control Manager"

    assert chain.binding is not None
    for obj in chain.objects:
        assert obj.source.endswith("(OBJECTS.DATA)")


def test_correlate_complete_chain_using_full_object_paths() -> None:
    filter_obj = make_filter(SUBSCRIPTION_NS, "MaliciousFilter")
    consumer_obj = make_script_consumer(SUBSCRIPTION_NS, "MaliciousConsumer", 'CreateObject("WScript.Shell")')
    binding_obj = make_binding(SUBSCRIPTION_NS, filter_obj.object_path, consumer_obj.object_path)

    report = correlate_subscriptions([filter_obj], [consumer_obj], [binding_obj])

    assert len(report.complete_chains) == 1
    chain = report.complete_chains[0]
    assert chain.filter is filter_obj
    assert chain.consumer is consumer_obj
    assert chain.binding is binding_obj
    assert chain.consumer.payload_properties["ScriptText"] == 'CreateObject("WScript.Shell")'
    assert {obj.source for obj in chain.objects} == {f"fixture:{SUBSCRIPTION_NS}:ActiveScriptEventConsumer"} | {
        f"fixture:{SUBSCRIPTION_NS}:{name}" for name in ("__EventFilter", "__FilterToConsumerBinding")
    }
    rendered = report.render_text()
    assert "CreateObject" in rendered
    assert "query:" in rendered


def test_missing_filter_is_reported_with_binding_source() -> None:
    consumer_obj = make_script_consumer(SUBSCRIPTION_NS, "OrphanedByFilter", "WScript.Echo 1")
    binding_obj = make_binding(
        SUBSCRIPTION_NS,
        '__EventFilter.Name="GoneFilter"',
        consumer_obj.object_path,
    )

    report = correlate_subscriptions([], [consumer_obj], [binding_obj])

    assert len(report.chains) == 1
    chain = report.chains[0]
    assert chain.status is LinkStatus.MISSING_FILTER
    assert chain.filter is None
    assert chain.consumer is consumer_obj
    assert chain.binding is binding_obj
    assert any("missing filter" in issue and "GoneFilter" in issue for issue in chain.issues)
    assert binding_obj.object_path in chain.issues[0]
    assert report.complete_chains == ()


def test_missing_consumer_is_reported_with_reference_details() -> None:
    filter_obj = make_filter(SUBSCRIPTION_NS, "BoundFilter")
    binding_obj = make_binding(
        SUBSCRIPTION_NS,
        filter_obj.object_path,
        'CommandLineEventConsumer.Name="GoneConsumer"',
    )

    report = correlate_subscriptions([filter_obj], [], [binding_obj])

    assert len(report.chains) == 1
    chain = report.chains[0]
    assert chain.status is LinkStatus.MISSING_CONSUMER
    assert chain.consumer is None
    assert chain.filter is filter_obj
    issue = chain.issues[0]
    assert "missing consumer" in issue
    assert "commandlineeventconsumer" in issue
    assert "'name': 'GoneConsumer'" in issue


def test_script_text_without_binding_is_not_a_subscription() -> None:
    filter_obj = make_filter(SUBSCRIPTION_NS, "LooseFilter")
    consumer_obj = make_script_consumer(SUBSCRIPTION_NS, "LooseConsumer", 'GetObject("winmgmts:")')

    report = correlate_subscriptions([filter_obj], [consumer_obj], [])

    assert report.complete_chains == ()
    assert {chain.status for chain in report.chains} == {
        LinkStatus.UNBOUND_FILTER,
        LinkStatus.UNBOUND_CONSUMER,
    }
    assert len(report.orphan_filters) == 1
    assert len(report.orphan_consumers) == 1
    orphan_consumer = report.orphan_consumers[0].consumer
    assert orphan_consumer is not None
    assert "GetObject" in orphan_consumer.payload_properties["ScriptText"]
    assert all(chain.binding is None for chain in report.chains)


def test_same_named_objects_in_different_namespaces_are_not_cross_linked() -> None:
    shared_name = "SameName"
    sub_filter = make_filter(SUBSCRIPTION_NS, shared_name)
    other_filter = make_filter(OTHER_NS, shared_name)
    sub_consumer = make_script_consumer(SUBSCRIPTION_NS, shared_name, 'MsgBox "sub"')
    other_consumer = make_script_consumer(OTHER_NS, shared_name, 'MsgBox "other"')

    sub_binding = make_binding(SUBSCRIPTION_NS, sub_filter.object_path, sub_consumer.object_path)
    other_binding = make_binding(OTHER_NS, other_filter.object_path, other_consumer.object_path)

    report = correlate_subscriptions(
        [sub_filter, other_filter],
        [sub_consumer, other_consumer],
        [sub_binding, other_binding],
    )

    assert len(report.complete_chains) == 2
    linked = {
        (
            chain.filter.namespace,
            chain.consumer.namespace,
            chain.consumer.payload_properties["ScriptText"],
        )
        for chain in report.complete_chains
    }
    assert linked == {
        (SUBSCRIPTION_NS, SUBSCRIPTION_NS, 'MsgBox "sub"'),
        (OTHER_NS, OTHER_NS, 'MsgBox "other"'),
    }

    # A relative reference stays inside the binding's own namespace even when a
    # same-named object exists elsewhere.
    relative_binding = make_binding(
        OTHER_NS,
        f'__EventFilter.Name="{shared_name}"',
        f'ActiveScriptEventConsumer.Name="{shared_name}"',
    )
    relative_report = correlate_subscriptions(
        [sub_filter, other_filter],
        [sub_consumer, other_consumer],
        [relative_binding],
    )
    relative_chain = relative_report.complete_chains[0]
    assert relative_chain.filter is other_filter
    assert relative_chain.consumer is other_consumer


def test_binding_with_both_references_missing() -> None:
    binding_obj = make_binding(
        SUBSCRIPTION_NS,
        '__EventFilter.Name="NoFilter"',
        'CommandLineEventConsumer.Name="NoConsumer"',
    )

    report = correlate_subscriptions([], [], [binding_obj])

    chain = report.chains[0]
    assert chain.status is LinkStatus.MISSING_BOTH
    assert chain.filter is None
    assert chain.consumer is None
    assert len(chain.issues) == 2


@pytest.mark.parametrize(
    ("reference", "expected_class", "expected_keys"),
    [
        (
            '__EventFilter.Name="SCM Event Log Filter"',
            "__eventfilter",
            {"name": "SCM Event Log Filter"},
        ),
        (
            '//./root/subscription:NTEventLogEventConsumer.Name="SCM Event Log Consumer"',
            "nteventlogeventconsumer",
            {"name": "SCM Event Log Consumer"},
        ),
        (
            r'\\.\root\subscription:CommandLineEventConsumer.Name="a,b=c"',
            "commandlineeventconsumer",
            {"name": "a,b=c"},
        ),
    ],
)
def test_parse_reference_forms(reference: str, expected_class: str, expected_keys: dict[str, str]) -> None:
    parsed = parse_reference(reference, SUBSCRIPTION_NS)
    assert parsed.valid
    assert parsed.namespace == SUBSCRIPTION_NS
    assert parsed.class_name == expected_class
    assert parsed.keys == expected_keys


def test_parse_reference_binding_value_with_nested_reference() -> None:
    raw = 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'
    parsed = parse_reference(raw, SUBSCRIPTION_NS)
    assert parsed.valid
    assert parsed.class_name == "nteventlogeventconsumer"
    assert parsed.keys == {"name": "SCM Event Log Consumer"}


def test_parse_reference_without_namespace_is_invalid() -> None:
    parsed = parse_reference('__EventFilter.Name="Orphan"')
    assert not parsed.valid
    assert parsed.error == "reference has no namespace"


def test_object_path_roundtrip_preserves_embedded_quotes() -> None:
    path = build_object_path(SUBSCRIPTION_NS, "__FilterToConsumerBinding", {"Filter": '__EventFilter.Name="x"'})
    parsed = parse_reference(path)
    assert parsed.valid
    assert parsed.class_name == "__filtertoconsumerbinding"
    assert parsed.keys == {"filter": '__EventFilter.Name="x"'}


def test_enumerate_skips_unknown_namespace() -> None:
    class DummyCIM:
        root = None

        def namespace(self, name: str):
            raise IndexError(name)

    report = enumerate_subscriptions(DummyCIM(), ["root\\does_not_exist"])  # type: ignore[arg-type]
    assert report.chains == ()
