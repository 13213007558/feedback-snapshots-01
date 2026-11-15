"""Offline enumeration of WMI permanent event subscription evidence.

A permanent WMI event subscription consists of three linked objects:

* an ``__EventFilter`` (the WQL event query),
* an ``__EventConsumer`` derivative (the action to run), and
* an ``__FilterToConsumerBinding`` that ties the two together.

This module only *parses* an offline repository. It never evaluates a query,
executes a command or runs a script. Objects are correlated strictly by their
full object path and instance keys, so objects with the same key in different
namespaces can never be linked together. Objects that cannot be connected are
preserved and reported separately: a script body on an unbound consumer is not
evidence of a working permanent subscription.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.cim.cim import CIM, Instance, Namespace

FILTER_CLASS = "__EventFilter"
BINDING_CLASS = "__FilterToConsumerBinding"
CONSUMER_BASE_CLASS = "__EventConsumer"

# Properties that carry the persisted, actionable content of each consumer type.
CONSUMER_PAYLOAD_PROPERTIES: dict[str, tuple[str, ...]] = {
    "ActiveScriptEventConsumer": ("ScriptText", "ScriptFilename", "ScriptingEngine", "Name"),
    "CommandLineEventConsumer": (
        "CommandLineTemplate",
        "ExecutablePath",
        "CommandLine",
        "WorkingDirectory",
        "Name",
    ),
    "LogFileEventConsumer": ("FileName", "Text", "IsUnicode", "LineSeparator", "Name"),
    "NTEventLogEventConsumer": ("SourceName", "EventID", "EventType", "Category", "InsertionStringTemplates", "Name"),
    "SMTPEventConsumer": (
        "SMTPServer",
        "ToLine",
        "CcLine",
        "BccLine",
        "ReplyToLine",
        "HeaderFields",
        "Message",
        "Name",
    ),
}


class LinkStatus(Enum):
    """State of a :class:`SubscriptionChain`."""

    COMPLETE = "complete"
    MISSING_FILTER = "missing_filter"
    MISSING_CONSUMER = "missing_consumer"
    MISSING_BOTH = "missing_filter_and_consumer"
    UNBOUND_FILTER = "unbound_filter"
    UNBOUND_CONSUMER = "unbound_consumer"


@dataclass(frozen=True, slots=True)
class ObjectReference:
    """A parsed reference found on a binding (``Filter`` / ``Consumer``)."""

    raw: str
    namespace: str | None
    class_name: str | None
    keys: dict[str, str]
    valid: bool
    error: str | None = None

    @property
    def identity(self) -> tuple[str, str, tuple[tuple[str, str], ...]] | None:
        """The ``(namespace, class, keys)`` identity, or ``None`` when invalid."""
        if not self.valid or self.namespace is None or self.class_name is None:
            return None
        return (self.namespace, self.class_name, tuple(sorted(self.keys.items())))


@dataclass(frozen=True, slots=True)
class EvidenceObject:
    """A single filter, consumer or binding instance parsed from the repository.

    Attributes:
        kind: ``filter``, ``consumer`` or ``binding``.
        namespace: Full namespace of the object (e.g. ``root\\subscription``).
        class_name: Concrete class that instantiates the object.
        key: Instance key property names and their values.
        properties: Every initialized instance property (raw, unevaluated).
        object_path: Canonical full object path used for correlation.
        source: Where the object was read from.
    """

    kind: str
    namespace: str
    class_name: str
    key: dict[str, str]
    properties: dict[str, object]
    object_path: str
    source: str

    @property
    def identity(self) -> tuple[str, str, tuple[tuple[str, str], ...]]:
        # Normalize class and key names to lowercase so this matches the
        # identity produced by parse_reference() regardless of WMI casing.
        normalized_keys = tuple(sorted((name.lower(), value) for name, value in self.key.items()))
        return (self.namespace, self.class_name.lower(), normalized_keys)

    @property
    def payload_properties(self) -> dict[str, object]:
        """The persisted execution content, depending on the consumer type."""
        if self.kind != "consumer":
            return {}
        wanted = CONSUMER_PAYLOAD_PROPERTIES.get(self.class_name)
        if wanted is None:
            return dict(self.properties)
        return {name: self.properties[name] for name in wanted if name in self.properties}


@dataclass(frozen=True, slots=True)
class SubscriptionChain:
    """A correlated (or partially correlated) permanent subscription."""

    binding: EvidenceObject | None
    filter: EvidenceObject | None
    consumer: EvidenceObject | None
    filter_reference: ObjectReference | None = None
    consumer_reference: ObjectReference | None = None
    issues: tuple[str, ...] = field(default=())

    @property
    def status(self) -> LinkStatus:
        if self.binding is None:
            return LinkStatus.UNBOUND_FILTER if self.filter is not None else LinkStatus.UNBOUND_CONSUMER

        missing_filter = self.filter is None
        missing_consumer = self.consumer is None
        if missing_filter and missing_consumer:
            return LinkStatus.MISSING_BOTH
        if missing_filter:
            return LinkStatus.MISSING_FILTER
        if missing_consumer:
            return LinkStatus.MISSING_CONSUMER
        return LinkStatus.COMPLETE

    @property
    def is_complete(self) -> bool:
        return self.status is LinkStatus.COMPLETE

    @property
    def objects(self) -> Iterator[EvidenceObject]:
        for obj in (self.binding, self.filter, self.consumer):
            if obj is not None:
                yield obj

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(obj.source for obj in self.objects))


@dataclass(frozen=True, slots=True)
class SubscriptionReport:
    """Result of correlating all subscription evidence in a repository."""

    chains: tuple[SubscriptionChain, ...]

    @property
    def complete_chains(self) -> tuple[SubscriptionChain, ...]:
        return tuple(chain for chain in self.chains if chain.is_complete)

    @property
    def incomplete_chains(self) -> tuple[SubscriptionChain, ...]:
        return tuple(chain for chain in self.chains if not chain.is_complete)

    @property
    def orphan_filters(self) -> tuple[SubscriptionChain, ...]:
        return tuple(chain for chain in self.chains if chain.status is LinkStatus.UNBOUND_FILTER)

    @property
    def orphan_consumers(self) -> tuple[SubscriptionChain, ...]:
        return tuple(chain for chain in self.chains if chain.status is LinkStatus.UNBOUND_CONSUMER)

    def render_text(self) -> str:
        """Render a human-readable, evidence-oriented report."""
        lines: list[str] = []
        for index, chain in enumerate(self.chains, start=1):
            lines.append(f"[{index}] {chain.status.value}")
            for issue in chain.issues:
                lines.append(f"    issue: {issue}")
            if chain.binding is not None:
                lines.append(f"    binding:  {chain.binding.object_path}")
                lines.append(f"        source: {chain.binding.source}")
            if chain.filter is not None:
                lines.append(f"    filter:   {chain.filter.object_path}")
                event_namespace = chain.filter.properties.get("EventNamespace", chain.filter.namespace)
                lines.append(f"        namespace:  {event_namespace}")
                lines.append(f"        language:   {chain.filter.properties.get('QueryLanguage', 'WQL')}")
                lines.append(f"        query:      {chain.filter.properties.get('Query', '')}")
                lines.append(f"        source: {chain.filter.source}")
            if chain.consumer is not None:
                lines.append(f"    consumer: {chain.consumer.object_path}")
                lines.append(f"        type: {chain.consumer.class_name}")
                payload = chain.consumer.payload_properties
                for name, value in payload.items():
                    lines.append(f"        {name}: {_shorten(value)}")
                lines.append(f"        source: {chain.consumer.source}")
            lines.append("")
        return "\n".join(lines).rstrip()


def build_object_path(namespace: str, class_name: str, key: dict[str, str]) -> str:
    """Build a canonical full object path (``\\\\.\\ns:Class.Key="v"``)."""
    return f"\\\\.\\{namespace}:{class_name}.{_render_key(key)}"


def parse_reference(reference: str, default_namespace: str | None = None) -> ObjectReference:
    """Parse a binding reference without evaluating or executing anything.

    Both full references (``//./root/sub:__EventFilter.Name="x"``) and
    namespace-relative references (``__EventFilter.Name="x"``) are supported.
    The class/key boundary and the individual keys are located with quote
    awareness, so dots and commas inside quoted values (including binding keys
    whose value is itself a reference) are preserved.
    """
    raw = reference
    text = reference.strip()
    text = text.removeprefix("winmgmts:")

    # Normalize the path/namespace portion only, so backslashes inside quoted
    # key values (e.g. escaped quotes, UNC executable paths) are preserved.
    path_end = _first_unquoted(text, ":")
    if path_end is not None:
        head, tail = text[:path_end], text[path_end + 1 :]
        head = head.replace("\\", "/")
        head = head.removeprefix("//").lstrip("/")
        if "/" in head:
            head = head.partition("/")[2]
        text = f"{head}:{tail}" if head else tail

    namespace = default_namespace
    if ":" in text:
        namespace_text, _, text = text.partition(":")
        namespace = namespace_text.replace("/", "\\").lower()

    split_at = _first_unquoted(text, ".")
    if split_at is None:
        return ObjectReference(raw, namespace, None, {}, False, "reference has no class and key section")

    class_name = text[:split_at]
    key_text = text[split_at + 1 :]
    if not class_name:
        return ObjectReference(raw, namespace, None, {}, False, "reference has no class name")

    keys: dict[str, str] = {}
    try:
        for key_part in _split_key_values(key_text):
            key_name, equals, value = key_part.partition("=")
            if not equals:
                raise ValueError(f"malformed key expression: {key_part}")
            keys[key_name.strip().lower()] = _unquote(value.strip())
    except ValueError as exc:
        return ObjectReference(raw, namespace, class_name, {}, False, str(exc))

    if namespace is None:
        return ObjectReference(raw, None, class_name, keys, False, "reference has no namespace")

    return ObjectReference(raw, namespace, class_name.lower(), keys, True)


def correlate_subscriptions(
    filters: Iterable[EvidenceObject],
    consumers: Iterable[EvidenceObject],
    bindings: Iterable[EvidenceObject],
) -> SubscriptionReport:
    """Correlate subscription evidence by full object path and instance keys.

    Objects are indexed by their ``(namespace, class, keys)`` identity. A
    reference can therefore only resolve inside the namespace it names; two
    same-named objects in different namespaces are never linked.
    """
    filter_map = _index_objects(filters)
    consumer_map = _index_objects(consumers)

    chains: list[SubscriptionChain] = []
    bound_filters: set[object] = set()
    bound_consumers: set[object] = set()

    for binding in bindings:
        issues: list[str] = []
        filter_ref = _binding_reference(binding, "Filter", binding.namespace)
        consumer_ref = _binding_reference(binding, "Consumer", binding.namespace)

        linked_filter = _resolve_reference(filter_ref, filter_map, "filter", binding, issues)
        linked_consumer = _resolve_reference(consumer_ref, consumer_map, "consumer", binding, issues)

        if linked_filter is not None:
            bound_filters.add(linked_filter.identity)
        if linked_consumer is not None:
            bound_consumers.add(linked_consumer.identity)

        chains.append(
            SubscriptionChain(
                binding=binding,
                filter=linked_filter,
                consumer=linked_consumer,
                filter_reference=filter_ref,
                consumer_reference=consumer_ref,
                issues=tuple(issues),
            )
        )

    for evidence_filter in filters:
        if evidence_filter.identity not in bound_filters:
            chains.append(SubscriptionChain(binding=None, filter=evidence_filter, consumer=None))

    for evidence_consumer in consumers:
        if evidence_consumer.identity not in bound_consumers:
            chains.append(SubscriptionChain(binding=None, filter=None, consumer=evidence_consumer))

    return SubscriptionReport(tuple(chains))


DEFAULT_SUBSCRIPTION_NAMESPACES = ("root\\subscription",)

# Concrete consumer classes shipped with WMI. Custom consumers are discovered
# separately through the __EventConsumer derivation chain.
KNOWN_CONSUMER_CLASSES = tuple(CONSUMER_PAYLOAD_PROPERTIES)


def enumerate_subscriptions(
    cim: CIM,
    namespaces: Iterable[str] | None = None,
) -> SubscriptionReport:
    """Enumerate and correlate subscription evidence in an offline repository.

    Permanent WMI subscriptions live in dedicated namespaces, by default
    ``root\\subscription``. Extra namespaces can be passed explicitly; each is
    resolved independently so same-named objects are never linked across them.

    Args:
        cim: The parsed offline repository.
        namespaces: Namespaces to scan. Defaults to
            :data:`DEFAULT_SUBSCRIPTION_NAMESPACES`.

    Returns:
        A report with every complete and incomplete chain.
    """
    namespace_names = tuple(DEFAULT_SUBSCRIPTION_NAMESPACES) if namespaces is None else tuple(namespaces)

    filters: list[EvidenceObject] = []
    consumers: list[EvidenceObject] = []
    bindings: list[EvidenceObject] = []

    for namespace in _resolve_namespaces(cim, namespace_names):
        for instance in _safe_instances(namespace, FILTER_CLASS):
            filters.append(_instance_to_evidence(instance, "filter"))

        for instance in _safe_instances(namespace, BINDING_CLASS):
            bindings.append(_instance_to_evidence(instance, "binding"))

        for class_name in _consumer_class_names(namespace):
            for instance in _safe_instances(namespace, class_name):
                consumers.append(_instance_to_evidence(instance, "consumer"))

    return correlate_subscriptions(filters, consumers, bindings)


def _resolve_namespaces(cim: CIM, namespace_names: Iterable[str]) -> Iterator[Namespace]:
    for raw_name in namespace_names:
        name = raw_name.lower()
        try:
            parent_name, _, child = name.rpartition("\\")
            parent = cim.namespace(parent_name) if parent_name else cim.root
            yield parent.namespace(child)
        except IndexError:
            continue


def _consumer_class_names(namespace: Namespace) -> list[str]:
    available = {class_.name for class_ in namespace.classes}
    names = [name for name in KNOWN_CONSUMER_CLASSES if name in available]

    # Pick up custom __EventConsumer derivatives that are not known up front.
    for name in available.difference(names):
        try:
            derivation = {ancestor.name for ancestor in namespace.class_(name).derivation}
        except Exception:
            # Corrupt class definitions must still leave other evidence usable.
            continue
        if CONSUMER_BASE_CLASS in derivation:
            names.append(name)
    return names


def _safe_instances(namespace: Namespace, class_name: str) -> list[Instance]:
    try:
        return list(namespace.class_(class_name).instances)
    except Exception:
        # A broken class must not abort the whole enumeration.
        return []


def _instance_to_evidence(instance: Instance, kind: str) -> EvidenceObject:
    properties = {name: prop.value for name, prop in instance.properties.items() if prop.is_initialized}
    key = {name: str(value) for name, value in instance.key.items()}
    namespace = instance.namespace.name.lower()
    class_name = instance.name
    source = f"{namespace}:{class_name}.{_render_key(key)} (OBJECTS.DATA)"
    return EvidenceObject(
        kind=kind,
        namespace=namespace,
        class_name=class_name,
        key=key,
        properties=properties,
        object_path=build_object_path(namespace, class_name, key),
        source=source,
    )


def _index_objects(objects: Iterable[EvidenceObject]) -> dict[object, EvidenceObject]:
    indexed: dict[object, EvidenceObject] = {}
    for obj in objects:
        indexed.setdefault(obj.identity, obj)
    return indexed


def _binding_reference(binding: EvidenceObject, prop: str, namespace: str) -> ObjectReference | None:
    raw = binding.properties.get(prop)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return parse_reference(raw, namespace)


def _resolve_reference(
    reference: ObjectReference | None,
    objects: dict[object, EvidenceObject],
    label: str,
    binding: EvidenceObject,
    issues: list[str],
) -> EvidenceObject | None:
    if reference is None:
        issues.append(f"binding {binding.object_path} has no {label} reference")
        return None
    if not reference.valid:
        issues.append(
            f"binding {binding.object_path} has unparseable {label} reference "
            f"{reference.raw!r}: {reference.error}"
        )
        return None

    match = objects.get(reference.identity)
    if match is None:
        issues.append(
            f"binding {binding.object_path} references missing {label} {reference.raw!r} "
            f"(namespace={reference.namespace}, class={reference.class_name}, keys={dict(reference.keys)})"
        )
    return match


def _split_key_values(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    quote_char = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quoted:
            current.append(char)
            if char == "\\" and index + 1 < len(text):
                current.append(text[index + 1])
                index += 2
                continue
            if char == quote_char:
                quoted = False
        elif char in ("'", '"'):
            quoted = True
            quote_char = char
            current.append(char)
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _render_key(key: dict[str, str]) -> str:
    return ",".join(f'{name}="{_quote(value)}"' for name, value in key.items())


def _quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _first_unquoted(text: str, needle: str) -> int | None:
    quoted = False
    quote_char = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quoted:
            if char == "\\" and index + 1 < len(text):
                index += 2
                continue
            if char == quote_char:
                quoted = False
        elif char in ("'", '"'):
            quoted = True
            quote_char = char
        elif char == needle:
            return index
        index += 1
    return None


def _shorten(value: object, limit: int = 160) -> str:
    text = repr(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


# Re-exported so callers can reuse the repository path parser if desired.
__all__ = [
    "CONSUMER_PAYLOAD_PROPERTIES",
    "EvidenceObject",
    "LinkStatus",
    "ObjectReference",
    "SubscriptionChain",
    "SubscriptionReport",
    "build_object_path",
    "correlate_subscriptions",
    "enumerate_subscriptions",
    "parse_reference",
]
