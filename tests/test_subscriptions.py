from __future__ import annotations

from typing import Any, BinaryIO

from dissect.cim.cim import CIM
from dissect.cim.subscriptions import (
    BindingEvidence,
    EventConsumerEvidence,
    EventFilterEvidence,
    correlate,
    enumerate_subscriptions,
)


class StubProperty:
    def __init__(self, value: Any, initialized: bool = True):
        self._value = value
        self.is_initialized = initialized

    @property
    def value(self) -> Any:
        if not self.is_initialized:
            raise ValueError("Property is not initialized")
        return self._value


class StubNamespace:
    def __init__(self, name: str):
        self.name = name


class StubClass:
    def __init__(self, name: str):
        self.name = name


class StubInstance:
    """Minimal stand-in for dissect.cim.cim.Instance."""

    def __init__(self, namespace: str, class_name: str, key: dict[str, Any], properties: dict[str, Any]):
        self.namespace = StubNamespace(namespace)
        self.class_ = StubClass(class_name)
        self.key = key
        self.properties = {name: StubProperty(value) for name, value in properties.items()}


def make_filter(
    namespace: str,
    name: str,
    query: str = "select * from __InstanceCreationEvent within 5 where TargetInstance isa 'Win32_Process'",
    query_language: str = "WQL",
    event_namespace: str = "root\\cimv2",
) -> EventFilterEvidence:
    return EventFilterEvidence.from_instance(
        StubInstance(
            namespace,
            "__EventFilter",
            {"Name": name},
            {
                "Name": name,
                "Query": query,
                "QueryLanguage": query_language,
                "EventNamespace": event_namespace,
                "CreatorSID": [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
            },
        )
    )


def make_consumer(
    namespace: str,
    name: str,
    class_name: str = "CommandLineEventConsumer",
    **properties: Any,
) -> EventConsumerEvidence:
    return EventConsumerEvidence.from_instance(
        StubInstance(namespace, class_name, {"Name": name}, {"Name": name, **properties})
    )


def make_binding(namespace: str, filter_path: str, consumer_path: str) -> BindingEvidence:
    return BindingEvidence.from_instance(
        StubInstance(
            namespace,
            "__FilterToConsumerBinding",
            {"Filter": filter_path, "Consumer": consumer_path},
            {"Filter": filter_path, "Consumer": consumer_path},
        )
    )


def test_complete_chain_in_sample_repository(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    report = enumerate_subscriptions(repo)

    assert len(report.chains) == 1
    assert report.complete_chains == report.chains
    assert not report.broken_chains
    assert not report.orphan_filters
    assert not report.orphan_consumers

    chain = report.chains[0]
    assert chain.status == "complete"

    # Every conclusion carries its object source, all from root\subscription.
    assert chain.binding.source.startswith("root\\subscription:__FilterToConsumerBinding.")
    assert chain.filter is not None
    assert chain.consumer is not None
    assert chain.filter.source == 'root\\subscription:__EventFilter.Name="SCM Event Log Filter"'
    assert chain.consumer.source == 'root\\subscription:NTEventLogEventConsumer.Name="SCM Event Log Consumer"'

    # Event query, language and namespace of the persisted filter.
    assert chain.filter.name == "SCM Event Log Filter"
    assert chain.filter.query == "select * from MSFT_SCMEventLogEvent"
    assert chain.filter.query_language == "WQL"
    assert chain.filter.event_namespace == "root\\cimv2"

    # Consumer type and its persisted execution content (parse-only).
    assert chain.consumer.consumer_type == "NTEventLogEventConsumer"
    assert chain.consumer.name == "SCM Event Log Consumer"
    assert chain.consumer.payload["SourceName"] == "Service Control Manager"
    assert chain.consumer.payload["EventType"] == 1


def test_missing_filter_chain() -> None:
    consumer = make_consumer("root\\subscription", "c1", CommandLineTemplate="powershell.exe -enc AAAA")
    binding = make_binding(
        "root\\subscription",
        '__EventFilter.Name="gone"',
        'CommandLineEventConsumer.Name="c1"',
    )

    report = correlate([], [consumer], [binding])

    assert not report.complete_chains
    assert len(report.broken_chains) == 1
    chain = report.broken_chains[0]
    assert chain.status == "missing-filter"
    assert chain.filter is None
    assert chain.consumer is consumer
    # The binding still records where the missing filter was expected.
    assert chain.binding.filter_path == '__EventFilter.Name="gone"'
    assert chain.binding.source.startswith("root\\subscription:__FilterToConsumerBinding.")
    # The consumer is bound, so it is not an orphan.
    assert not report.orphan_consumers


def test_missing_consumer_chain() -> None:
    filter_ = make_filter("root\\subscription", "f1")
    binding = make_binding(
        "root\\subscription",
        '__EventFilter.Name="f1"',
        'ActiveScriptEventConsumer.Name="gone"',
    )

    report = correlate([filter_], [], [binding])

    assert not report.complete_chains
    assert len(report.broken_chains) == 1
    chain = report.broken_chains[0]
    assert chain.status == "missing-consumer"
    assert chain.filter is filter_
    assert chain.consumer is None
    assert chain.binding.consumer_path == 'ActiveScriptEventConsumer.Name="gone"'
    assert not report.orphan_filters


def test_orphan_filter_and_consumer_without_binding() -> None:
    filter_ = make_filter("root\\subscription", "lonely-filter")
    consumer = make_consumer(
        "root\\subscription",
        "lonely-consumer",
        class_name="ActiveScriptEventConsumer",
        ScriptText='Set objShell = CreateObject("Wscript.Shell")',
        ScriptingEngine="VBScript",
    )

    report = correlate([filter_], [consumer], [])

    assert report.chains == []
    assert report.orphan_filters == [filter_]
    assert report.orphan_consumers == [consumer]

    # Persisted script text is evidence, but without a binding it is not a
    # valid permanent subscription.
    orphan = report.orphan_consumers[0]
    assert orphan.consumer_type == "ActiveScriptEventConsumer"
    assert orphan.payload["ScriptText"] == 'Set objShell = CreateObject("Wscript.Shell")'
    assert orphan.source == 'root\\subscription:ActiveScriptEventConsumer.Name="lonely-consumer"'
    assert not report.complete_chains


def test_same_named_objects_not_linked_across_namespaces() -> None:
    filter_a = make_filter("root\\alpha", "dup", query="select * from __InstanceCreationEvent")
    filter_b = make_filter("root\\beta", "dup", query="select * from __InstanceDeletionEvent")
    # Relative reference: resolves against the binding's own namespace.
    binding_relative = make_binding("root\\alpha", '__EventFilter.Name="dup"', 'CommandLineEventConsumer.Name="c"')
    # Rooted reference: resolves against the namespace embedded in the path.
    binding_rooted = make_binding(
        "root\\alpha",
        '\\\\.\\root\\beta:__EventFilter.Name="dup"',
        'CommandLineEventConsumer.Name="c"',
    )
    consumer = make_consumer("root\\alpha", "c")

    report = correlate([filter_a, filter_b], [consumer], [binding_relative, binding_rooted])

    relative_chain, rooted_chain = report.chains
    assert relative_chain.filter is filter_a
    assert rooted_chain.filter is filter_b
    # Both filters are bound exactly once, in their own namespace.
    assert not report.orphan_filters

    # Case-insensitive matching still respects namespace boundaries.
    binding_case = make_binding("root\\ALPHA", '__eventfilter.name="DUP"', 'commandlineeventconsumer.name="C"')
    report_case = correlate([filter_a, filter_b], [consumer], [binding_case])
    assert report_case.chains[0].filter is filter_a
    assert report_case.chains[0].consumer is consumer
