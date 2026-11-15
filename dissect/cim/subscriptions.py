"""Permanent WMI event subscription evidence enumeration.

Parses ``__EventFilter``, ``__EventConsumer`` (derived classes) and
``__FilterToConsumerBinding`` instances from an offline CIM repository and
correlates them into subscription chains.

Everything is parse-only: persisted execution content (command lines, script
text, ...) is extracted as evidence but never executed. Correlation happens on
full object identity (namespace + class + instance key), so same-named objects
in different namespaces are never linked together. A chain is only reported as
complete when a binding, its filter and its consumer all resolve; script text
or a command line on an unbound consumer does not constitute a valid permanent
subscription.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dissect.cim.c_cim import SYSTEM_NAMESPACE_NAME
from dissect.cim.exceptions import Error
from dissect.cim.utils import parse_object_path

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from dissect.cim.cim import CIM, Instance, Namespace

FILTER_CLASS_NAME = "__EventFilter"
BINDING_CLASS_NAME = "__FilterToConsumerBinding"
CONSUMER_BASE_CLASS_NAME = "__EventConsumer"

STANDARD_CONSUMER_CLASS_NAMES = (
    "ActiveScriptEventConsumer",
    "CommandLineEventConsumer",
    "LogFileEventConsumer",
    "NTEventLogEventConsumer",
    "SMTPEventConsumer",
)

# Persisted execution content per consumer type. These properties describe
# what would run when the subscription fires; they are reported, not run.
PAYLOAD_PROPERTIES = {
    "activescripteventconsumer": (
        "ScriptText",
        "ScriptFileName",
        "ScriptingEngine",
        "KillTimeout",
    ),
    "commandlineeventconsumer": (
        "CommandLineTemplate",
        "ExecutablePath",
        "WorkingDirectory",
        "RunInteractively",
    ),
    "logfileeventconsumer": (
        "Filename",
        "Text",
        "IsUnicode",
    ),
    "nteventlogeventconsumer": (
        "SourceName",
        "EventID",
        "EventType",
        "Category",
        "InsertionStringTemplates",
    ),
    "smtpeventconsumer": (
        "SMTPServer",
        "ToLine",
        "CcLine",
        "BccLine",
        "FromLine",
        "ReplyToLine",
        "Subject",
        "Message",
    ),
}

# Properties that never describe execution content.
_NON_PAYLOAD_PROPERTIES = {"Name", "CreatorSID"}


def _normalize_key(key: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(name).lower(), str(value).lower()) for name, value in key.items()))


def _format_key(key: Mapping[str, Any]) -> str:
    if not key:
        return "default"
    return ",".join(f'{name}="{value}"' for name, value in key.items())


@dataclass(frozen=True)
class ObjectRef:
    """Namespace- and key-qualified identity of a CIM instance.

    Comparison is case-insensitive on namespace, class and key components,
    matching WMI semantics. ``path`` preserves the original spelling for
    provenance reporting.
    """

    namespace: str
    class_name: str
    key: tuple[tuple[str, str], ...]
    path: str = field(compare=False)

    @classmethod
    def from_parts(cls, namespace: str, class_name: str, key: Mapping[str, Any]) -> ObjectRef:
        path = f"{namespace}:{class_name}.{_format_key(key)}"
        return cls(namespace.lower(), class_name.lower(), _normalize_key(key), path)

    def __str__(self) -> str:
        return self.path


def _initialized_properties(instance: Instance) -> dict[str, Any]:
    properties = {}
    for name, prop in instance.properties.items():
        if prop.is_initialized:
            properties[name] = prop.value
    return properties


@dataclass
class EventFilterEvidence:
    """An ``__EventFilter`` instance recovered from the repository."""

    ref: ObjectRef
    name: str | None
    query: str | None
    query_language: str | None
    event_namespace: str | None

    @property
    def source(self) -> str:
        return self.ref.path

    @classmethod
    def from_instance(cls, instance: Instance) -> EventFilterEvidence:
        properties = _initialized_properties(instance)
        ref = ObjectRef.from_parts(instance.namespace.name, instance.class_.name, instance.key)
        return cls(
            ref=ref,
            name=properties.get("Name"),
            query=properties.get("Query"),
            query_language=properties.get("QueryLanguage"),
            event_namespace=properties.get("EventNamespace"),
        )


@dataclass
class EventConsumerEvidence:
    """An ``__EventConsumer`` derived instance recovered from the repository."""

    ref: ObjectRef
    consumer_type: str
    name: str | None
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def source(self) -> str:
        return self.ref.path

    @property
    def payload(self) -> dict[str, Any]:
        """Persisted execution content of this consumer (parse-only)."""
        known = PAYLOAD_PROPERTIES.get(self.consumer_type.lower())
        if known is None:
            return {k: v for k, v in self.properties.items() if k not in _NON_PAYLOAD_PROPERTIES}
        return {k: self.properties[k] for k in known if k in self.properties}

    @classmethod
    def from_instance(cls, instance: Instance) -> EventConsumerEvidence:
        properties = _initialized_properties(instance)
        ref = ObjectRef.from_parts(instance.namespace.name, instance.class_.name, instance.key)
        return cls(
            ref=ref,
            consumer_type=instance.class_.name,
            name=properties.get("Name"),
            properties=properties,
        )


@dataclass
class BindingEvidence:
    """A ``__FilterToConsumerBinding`` instance recovered from the repository."""

    ref: ObjectRef
    filter_path: str | None
    consumer_path: str | None
    filter_ref: ObjectRef | None
    consumer_ref: ObjectRef | None

    @property
    def source(self) -> str:
        return self.ref.path

    @classmethod
    def from_instance(cls, instance: Instance) -> BindingEvidence:
        properties = _initialized_properties(instance)
        ref = ObjectRef.from_parts(instance.namespace.name, instance.class_.name, instance.key)
        filter_path = properties.get("Filter")
        consumer_path = properties.get("Consumer")
        return cls(
            ref=ref,
            filter_path=filter_path,
            consumer_path=consumer_path,
            filter_ref=_parse_ref(filter_path, instance.namespace) if filter_path else None,
            consumer_ref=_parse_ref(consumer_path, instance.namespace) if consumer_path else None,
        )


def _parse_ref(path: str, ns: Namespace) -> ObjectRef | None:
    """Resolve a persisted object path string to an ObjectRef.

    Relative paths resolve against the binding's own namespace, which is how
    WMI stores them; rooted paths carry their own namespace.
    """
    try:
        object_path = parse_object_path(path, ns)
    except (Error, RuntimeError):
        return None
    if not object_path.class_ or not object_path.instance:
        return None
    namespace = object_path.namespace or ns.name
    return ObjectRef.from_parts(namespace, object_path.class_, object_path.instance)


@dataclass
class SubscriptionChain:
    """A binding linked to its filter and consumer, when they resolve."""

    binding: BindingEvidence
    filter: EventFilterEvidence | None = None
    consumer: EventConsumerEvidence | None = None

    @property
    def status(self) -> str:
        missing = []
        if self.filter is None:
            missing.append("filter")
        if self.consumer is None:
            missing.append("consumer")
        return "complete" if not missing else "missing-" + "-and-".join(missing)

    @property
    def is_complete(self) -> bool:
        return self.filter is not None and self.consumer is not None


@dataclass
class SubscriptionReport:
    """Result of correlating all subscription evidence in a repository."""

    chains: list[SubscriptionChain]
    orphan_filters: list[EventFilterEvidence]
    orphan_consumers: list[EventConsumerEvidence]

    @property
    def complete_chains(self) -> list[SubscriptionChain]:
        return [chain for chain in self.chains if chain.is_complete]

    @property
    def broken_chains(self) -> list[SubscriptionChain]:
        return [chain for chain in self.chains if not chain.is_complete]


def correlate(
    filters: list[EventFilterEvidence],
    consumers: list[EventConsumerEvidence],
    bindings: list[BindingEvidence],
) -> SubscriptionReport:
    """Link bindings to filters and consumers by full object identity."""
    filters_by_ref = {evidence.ref: evidence for evidence in filters}
    consumers_by_ref = {evidence.ref: evidence for evidence in consumers}

    bound_filters = set()
    bound_consumers = set()
    chains = []
    for binding in bindings:
        filter_ = filters_by_ref.get(binding.filter_ref) if binding.filter_ref else None
        consumer = consumers_by_ref.get(binding.consumer_ref) if binding.consumer_ref else None
        if filter_ is not None:
            bound_filters.add(filter_.ref)
        if consumer is not None:
            bound_consumers.add(consumer.ref)
        chains.append(SubscriptionChain(binding=binding, filter=filter_, consumer=consumer))

    orphan_filters = [evidence for evidence in filters if evidence.ref not in bound_filters]
    orphan_consumers = [evidence for evidence in consumers if evidence.ref not in bound_consumers]
    return SubscriptionReport(chains=chains, orphan_filters=orphan_filters, orphan_consumers=orphan_consumers)


def iter_namespaces(cim: CIM) -> Iterator[Namespace]:
    """Walk every namespace in the repository, except the system namespace."""
    seen = set()
    stack = [cim.root]
    while stack:
        ns = stack.pop()
        name = ns.name.lower()
        if name in seen or name == SYSTEM_NAMESPACE_NAME.lower():
            continue
        seen.add(name)
        yield ns
        stack.extend(ns.namespaces)


def _iter_instances(ns: Namespace, class_name: str) -> Iterator[Instance]:
    try:
        class_ = ns.class_(class_name)
    except Error:
        return
    yield from class_.instances


def collect_filters(ns: Namespace) -> list[EventFilterEvidence]:
    return [EventFilterEvidence.from_instance(instance) for instance in _iter_instances(ns, FILTER_CLASS_NAME)]


def collect_bindings(ns: Namespace) -> list[BindingEvidence]:
    return [BindingEvidence.from_instance(instance) for instance in _iter_instances(ns, BINDING_CLASS_NAME)]


def _is_event_consumer(class_: Any) -> bool:
    if class_.name.lower() == CONSUMER_BASE_CLASS_NAME.lower():
        return False
    try:
        return any(c.name.lower() == CONSUMER_BASE_CLASS_NAME.lower() for c in class_.derivation)
    except Error:
        return False


def _discover_consumer_class_names(ns: Namespace) -> set[str]:
    """Scan a namespace's own class definitions for consumer-like classes.

    This parses every local class definition, which is expensive on large
    repositories; only used when custom consumer discovery is requested.
    """
    names = set()
    q = ns.cim.key().NS(ns.name).CD()
    for ref in q.references():
        try:
            class_def = ns.cim.get_class_definition(ref)
        except Error:
            continue
        if "consumer" in class_def.class_name.lower():
            names.add(class_def.class_name)
    return names


def collect_consumers(ns: Namespace, class_names: set[str] | None = None) -> list[EventConsumerEvidence]:
    evidence = []
    for class_name in sorted(class_names or STANDARD_CONSUMER_CLASS_NAMES):
        try:
            class_ = ns.class_(class_name)
        except Error:
            continue
        if not _is_event_consumer(class_):
            continue
        evidence.extend(EventConsumerEvidence.from_instance(instance) for instance in class_.instances)
    return evidence


def enumerate_subscriptions(cim: CIM, discover_custom_consumers: bool = False) -> SubscriptionReport:
    """Enumerate permanent event subscription evidence from a CIM repository.

    Consumer instances are collected for the standard consumer classes and for
    any consumer class referenced by a binding. Custom consumer classes that
    are only referenced by unbound (orphan) instances require
    ``discover_custom_consumers``, which scans every local class definition
    and is noticeably slower on large repositories.
    """
    namespaces = list(iter_namespaces(cim))

    filters = []
    bindings = []
    for ns in namespaces:
        filters.extend(collect_filters(ns))
        bindings.extend(collect_bindings(ns))

    # Consumer class names referenced by bindings, grouped by the namespace
    # the (parsed) reference points at.
    referenced: dict[str, set[str]] = {}
    for binding in bindings:
        if binding.consumer_ref is not None:
            referenced.setdefault(binding.consumer_ref.namespace, set()).add(binding.consumer_ref.class_name)

    consumers = []
    for ns in namespaces:
        class_names = set(STANDARD_CONSUMER_CLASS_NAMES)
        class_names.update(referenced.get(ns.name.lower(), ()))
        if discover_custom_consumers:
            class_names.update(_discover_consumer_class_names(ns))
        consumers.extend(collect_consumers(ns, class_names))

    return correlate(filters, consumers, bindings)
