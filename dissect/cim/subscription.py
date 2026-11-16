from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.cim.c_cim import SYSTEM_NAMESPACE_NAME
from dissect.cim.exceptions import ReferenceNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cim.cim import CIM

FILTER_CLASS = "__EventFilter"
BINDING_CLASS = "__FilterToConsumerBinding"
CONSUMER_SUFFIX = "EventConsumer"
BINDING_FILTER_FIELD = "Filter"
BINDING_CONSUMER_FIELD = "Consumer"

# The standard permanent WMI event consumers. Custom consumers are picked up
# indirectly through the Consumer reference found on bindings.
STANDARD_CONSUMER_CLASSES = (
    "ActiveScriptEventConsumer",
    "CommandLineEventConsumer",
    "LogFileEventConsumer",
    "NTEventLogEventConsumer",
    "SMTPEventConsumer",
)

# Classes looked up directly in every namespace via cheap index key lookups.
TARGET_CLASSES = (FILTER_CLASS, BINDING_CLASS, *STANDARD_CONSUMER_CLASSES)

# Failures that mean "this class/object is not present", which is normal.
MISSING_REFERENCE_ERRORS = (ReferenceNotFoundError, IndexError)


class ValueOrigin(str, Enum):
    """Where an instance property value came from."""

    EXPLICIT = "explicit"
    DEFAULT = "default"
    UNINITIALIZED = "uninitialized"
    UNRESOLVED = "unresolved"


class ObjectKind(str, Enum):
    FILTER = "filter"
    CONSUMER = "consumer"
    BINDING = "binding"


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CONTENT_CHANGED = "content_changed"
    RELATIONSHIP_CHANGED = "relationship_changed"
    UNDETERMINED = "undetermined"


class IssueScope(str, Enum):
    NAMESPACE = "namespace"
    OBJECT = "object"
    FIELD = "field"
    REFERENCE = "reference"


@dataclass(frozen=True)
class ObjectRef:
    """A namespace-qualified reference to a subscription object.

    The namespace is part of the identity: two objects with the same class and
    key but a different namespace are never merged.
    """

    namespace: str
    class_name: str
    key: str

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.namespace.lower(), self.class_name.lower(), self.key.lower())

    def __str__(self) -> str:
        return f"{self.namespace}!{self.class_name}[{self.key}]"


@dataclass(frozen=True)
class FieldValue:
    """A property value together with its origin.

    ``value`` is ``None`` for uninitialized/unresolved fields. The origin keeps
    an explicit instance value, a class default and an unreadable value apart
    even when their effective values coincide.
    """

    origin: ValueOrigin
    value: Any = None


@dataclass
class SubscriptionObject:
    ref: ObjectRef
    kind: ObjectKind
    fields: dict[str, FieldValue]
    filter_ref: ObjectRef | None = None
    consumer_ref: ObjectRef | None = None
    raw_filter: str | None = None
    raw_consumer: str | None = None


@dataclass(frozen=True)
class ExtractionIssue:
    """A read failure recorded while building a snapshot.

    A failure is never interpreted as the absence of an object. When it can be
    tied to an object identity it suppresses add/remove conclusions for that
    identity; otherwise it is only reported.
    """

    scope: IssueScope
    detail: str
    error: str
    ref: ObjectRef | None = None


@dataclass
class SubscriptionSnapshot:
    source: str
    objects: dict[tuple[str, str, str], SubscriptionObject] = field(default_factory=dict)
    issues: list[ExtractionIssue] = field(default_factory=list)

    def issue_identities(self, scope: IssueScope) -> set[tuple[str, str, str]]:
        return {issue.ref.identity for issue in self.issues if issue.scope == scope and issue.ref is not None}


@dataclass
class FieldDiff:
    name: str
    old: FieldValue | None
    new: FieldValue | None


@dataclass
class SubscriptionChange:
    change_type: ChangeType
    kind: ObjectKind
    ref: ObjectRef
    old: SubscriptionObject | None = None
    new: SubscriptionObject | None = None
    field_diffs: list[FieldDiff] = field(default_factory=list)
    undetermined_fields: list[str] = field(default_factory=list)
    old_target: ObjectRef | None = None
    new_target: ObjectRef | None = None
    reason: str | None = None


@dataclass
class SubscriptionDiff:
    left_source: str
    right_source: str
    changes: list[SubscriptionChange] = field(default_factory=list)
    issues: list[tuple[str, ExtractionIssue]] = field(default_factory=list)

    @property
    def has_semantic_changes(self) -> bool:
        return any(change.change_type is not ChangeType.UNDETERMINED for change in self.changes)

    def changes_of_type(self, change_type: ChangeType) -> list[SubscriptionChange]:
        return [change for change in self.changes if change.change_type is change_type]


def _read_field(prop: Any) -> FieldValue:
    if not prop.is_initialized:
        return FieldValue(ValueOrigin.UNINITIALIZED)
    if prop.is_default_value:
        return FieldValue(ValueOrigin.DEFAULT, prop.value)
    return FieldValue(ValueOrigin.EXPLICIT, prop.value)


def _split_top_level(text: str, separator: str) -> list[str]:
    parts: list[str] = []
    buffer = ""
    quoted = False
    quote_char = ""
    for char in text:
        if quoted:
            buffer += char
            if char == quote_char:
                quoted = False
        elif char in ('"', "'"):
            quoted = True
            quote_char = char
            buffer += char
        elif char == separator:
            parts.append(buffer)
            buffer = ""
        else:
            buffer += char
    parts.append(buffer)
    return parts


def parse_reference(raw: str, current_namespace: str) -> ObjectRef:
    """Parse a WMI reference string without touching the repository.

    Handles relative references (``Class.Name="x"``) and rooted references
    (``root/sub:Class.Name="x"`` and ``//./root/sub:Class.Name="x"``). Raises
    ``ValueError`` when the string cannot be interpreted as an object path.
    """

    text = raw.replace("\\", "/").strip()
    if text.startswith("//"):
        text = text[2:]
        _, _, text = text.partition("/")

    namespace = current_namespace
    if ":" in text:
        head, _, rest = text.partition(":")
        if "=" not in head and ("/" in head or head.lower().startswith("root")):
            namespace = head.replace("/", "\\")
            text = rest

    class_name, separator, key_part = text.partition(".")
    if not separator or not class_name.strip() or not key_part.strip():
        raise ValueError(f"Unparseable WMI reference: {raw!r}")

    key_pairs = []
    for pair in _split_top_level(key_part, ","):
        key_name, equals, raw_value = pair.partition("=")
        if not equals:
            raise ValueError(f"Unparseable WMI reference key: {raw!r}")
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        key_pairs.append(f'{key_name.strip()}="{value}"')

    return ObjectRef(namespace, class_name.strip(), ",".join(key_pairs))


def _iter_namespaces(snapshot: SubscriptionSnapshot, namespace: Any) -> Iterator[Any]:
    yield namespace
    try:
        children = list(namespace.namespaces)
    except Exception as exc:  # noqa: BLE001 - any parse failure is recorded, not fatal
        snapshot.issues.append(
            ExtractionIssue(
                IssueScope.NAMESPACE,
                f"Unable to enumerate child namespaces of {namespace.name}",
                repr(exc),
            )
        )
        return

    for child in children:
        if child.name.lower() == SYSTEM_NAMESPACE_NAME.lower():
            continue
        yield from _iter_namespaces(snapshot, child)


def _extract_object(
    snapshot: SubscriptionSnapshot,
    namespace_name: str,
    class_name: str,
    kind: ObjectKind,
    instance: Any,
) -> SubscriptionObject | None:
    try:
        key = str(instance.key)
    except Exception as exc:  # noqa: BLE001
        snapshot.issues.append(
            ExtractionIssue(
                IssueScope.OBJECT,
                f"Unable to read instance key of {namespace_name}!{class_name}",
                repr(exc),
            )
        )
        return None

    ref = ObjectRef(namespace_name, class_name, key)
    fields: dict[str, FieldValue] = {}
    try:
        properties = instance.properties
    except Exception as exc:  # noqa: BLE001
        snapshot.issues.append(
            ExtractionIssue(IssueScope.OBJECT, f"Unable to read properties of {ref}", repr(exc), ref)
        )
        return None

    for field_name, prop in properties.items():
        try:
            fields[field_name] = _read_field(prop)
        except Exception as exc:  # noqa: BLE001
            snapshot.issues.append(
                ExtractionIssue(
                    IssueScope.FIELD,
                    f"Unable to resolve field {field_name} of {ref}",
                    repr(exc),
                    ref,
                )
            )
            fields[field_name] = FieldValue(ValueOrigin.UNRESOLVED)

    subscription_object = SubscriptionObject(ref, kind, fields)

    if kind is ObjectKind.BINDING:
        subscription_object.raw_filter = _reference_raw(fields.get(BINDING_FILTER_FIELD))
        subscription_object.raw_consumer = _reference_raw(fields.get(BINDING_CONSUMER_FIELD))
        subscription_object.filter_ref = _resolve_reference(
            snapshot, ref, BINDING_FILTER_FIELD, subscription_object.raw_filter, namespace_name
        )
        subscription_object.consumer_ref = _resolve_reference(
            snapshot, ref, BINDING_CONSUMER_FIELD, subscription_object.raw_consumer, namespace_name
        )

    return subscription_object


def _reference_raw(field_value: FieldValue | None) -> str | None:
    if field_value is None or field_value.origin in (ValueOrigin.UNINITIALIZED, ValueOrigin.UNRESOLVED):
        return None
    return None if field_value.value is None else str(field_value.value)


def _resolve_reference(
    snapshot: SubscriptionSnapshot,
    binding_ref: ObjectRef,
    field_name: str,
    raw: str | None,
    namespace_name: str,
) -> ObjectRef | None:
    if raw is None:
        return None
    try:
        return parse_reference(raw, namespace_name)
    except ValueError as exc:
        snapshot.issues.append(
            ExtractionIssue(
                IssueScope.REFERENCE,
                f"Unable to resolve {field_name} reference {raw!r} of binding {binding_ref}",
                repr(exc),
                binding_ref,
            )
        )
        return None


def _extract_class(snapshot: SubscriptionSnapshot, namespace: Any, class_name: str, kind: ObjectKind) -> None:
    try:
        class_ = namespace.class_(class_name)
    except MISSING_REFERENCE_ERRORS:
        # The class simply does not exist in this namespace; nothing to extract.
        return
    except Exception as exc:  # noqa: BLE001
        snapshot.issues.append(
            ExtractionIssue(
                IssueScope.OBJECT,
                f"Unable to open class {namespace.name}!{class_name}",
                repr(exc),
            )
        )
        return

    try:
        instances = list(class_.instances)
    except Exception as exc:  # noqa: BLE001
        snapshot.issues.append(
            ExtractionIssue(
                IssueScope.OBJECT,
                f"Unable to enumerate instances of {namespace.name}!{class_.name}",
                repr(exc),
            )
        )
        return

    for instance in instances:
        try:
            extracted = _extract_object(snapshot, namespace.name, class_.name, kind, instance)
        except Exception as exc:  # noqa: BLE001
            snapshot.issues.append(
                ExtractionIssue(
                    IssueScope.OBJECT,
                    f"Unable to read instance of {namespace.name}!{class_.name}",
                    repr(exc),
                )
            )
            continue
        if extracted is not None:
            snapshot.objects[extracted.ref.identity] = extracted


def _extract_namespace(snapshot: SubscriptionSnapshot, namespace: Any) -> None:
    # First pass: direct, cheap index lookups for the standard classes. This
    # deliberately avoids enumerating every class definition in the namespace,
    # which is expensive on large namespaces such as root\\CIMV2.
    for class_name in TARGET_CLASSES:
        if class_name == FILTER_CLASS:
            kind = ObjectKind.FILTER
        elif class_name == BINDING_CLASS:
            kind = ObjectKind.BINDING
        else:
            kind = ObjectKind.CONSUMER
        _extract_class(snapshot, namespace, class_name, kind)

    # Second pass: custom consumers are not in the standard set, but every bound
    # consumer names its class through the binding's Consumer reference.
    consumer_classes = {
        obj.consumer_ref.class_name
        for obj in snapshot.objects.values()
        if obj.kind is ObjectKind.BINDING
        and obj.consumer_ref is not None
        and obj.consumer_ref.namespace.lower() == namespace.name.lower()
    }
    for class_name in sorted(consumer_classes):
        if class_name in TARGET_CLASSES or not class_name.lower().endswith(CONSUMER_SUFFIX.lower()):
            continue
        identity_seed = (namespace.name.lower(), class_name.lower())
        if any(identity[:2] == identity_seed for identity in snapshot.objects):
            continue
        _extract_class(snapshot, namespace, class_name, ObjectKind.CONSUMER)


def extract_subscriptions(cim: CIM, source: str) -> SubscriptionSnapshot:
    """Build a semantic snapshot of all permanent subscriptions in a repo.

    The snapshot only contains namespace/class/key identities and resolved
    field values. It never stores physical page numbers or index positions, so
    page migration and index reordering cannot influence a later comparison.
    """

    snapshot = SubscriptionSnapshot(source)
    for namespace in _iter_namespaces(snapshot, cim.root):
        _extract_namespace(snapshot, namespace)
    return snapshot


def _field_changed(left: FieldValue | None, right: FieldValue | None) -> bool:
    if left is None or right is None:
        return left is not right
    if ValueOrigin.UNRESOLVED in (left.origin, right.origin):
        return False
    return left.origin is not right.origin or left.value != right.value


def _is_unresolved(field_value: FieldValue | None) -> bool:
    return field_value is None or field_value.origin is ValueOrigin.UNRESOLVED


def _compare_object(
    left: SubscriptionObject,
    right: SubscriptionObject,
) -> SubscriptionChange | None:
    field_diffs: list[FieldDiff] = []
    undetermined_fields: list[str] = []

    for field_name in sorted(set(left.fields) | set(right.fields)):
        if left.kind is ObjectKind.BINDING and field_name in (BINDING_FILTER_FIELD, BINDING_CONSUMER_FIELD):
            continue
        old_value = left.fields.get(field_name)
        new_value = right.fields.get(field_name)
        if _is_unresolved(old_value) or _is_unresolved(new_value):
            undetermined_fields.append(field_name)
        elif _field_changed(old_value, new_value):
            field_diffs.append(FieldDiff(field_name, old_value, new_value))

    old_target = left.consumer_ref
    new_target = right.consumer_ref

    def _reference_changed(side_attr: str, raw_attr: str) -> bool:
        left_ref = getattr(left, side_attr)
        right_ref = getattr(right, side_attr)
        if (left_ref is None) != (right_ref is None):
            return True
        if left_ref is not None and left_ref.identity != right_ref.identity:
            return True
        # Both references are unresolvable: fall back to the raw reference
        # string so a redirect hidden behind a parse failure is still detected.
        if left_ref is None and getattr(left, raw_attr) != getattr(right, raw_attr):
            return True
        return False

    relationship_changed = left.kind is ObjectKind.BINDING and (
        _reference_changed("consumer_ref", "raw_consumer") or _reference_changed("filter_ref", "raw_filter")
    )

    if relationship_changed:
        change_type = ChangeType.RELATIONSHIP_CHANGED
    elif field_diffs:
        change_type = ChangeType.CONTENT_CHANGED
    elif undetermined_fields:
        change_type = ChangeType.UNDETERMINED
    else:
        return None

    return SubscriptionChange(
        change_type,
        left.kind,
        right.ref,
        old=left,
        new=right,
        field_diffs=field_diffs,
        undetermined_fields=undetermined_fields,
        old_target=old_target,
        new_target=new_target,
    )


def compare_snapshots(left: SubscriptionSnapshot, right: SubscriptionSnapshot) -> SubscriptionDiff:
    """Compare two semantic snapshots and report only provable changes.

    An object that is present on one side and unreadable on the other is
    reported as ``UNDETERMINED`` rather than added/removed. Physical layout is
    not part of the snapshot and therefore cannot produce a change.
    """

    diff = SubscriptionDiff(left.source, right.source)
    diff.issues.extend((left.source, issue) for issue in left.issues)
    diff.issues.extend((right.source, issue) for issue in right.issues)

    left_blocked = left.issue_identities(IssueScope.OBJECT)
    right_blocked = right.issue_identities(IssueScope.OBJECT)

    for identity in sorted(set(left.objects) | set(right.objects)):
        left_object = left.objects.get(identity)
        right_object = right.objects.get(identity)

        if left_object is not None and right_object is not None:
            change = _compare_object(left_object, right_object)
            if change is not None:
                diff.changes.append(change)
            continue

        if left_object is not None:
            if identity in right_blocked:
                diff.changes.append(
                    SubscriptionChange(
                        ChangeType.UNDETERMINED,
                        left_object.kind,
                        left_object.ref,
                        old=left_object,
                        reason="object exists on the left but could not be read on the right",
                    )
                )
            else:
                diff.changes.append(
                    SubscriptionChange(ChangeType.REMOVED, left_object.kind, left_object.ref, old=left_object)
                )
            continue

        assert right_object is not None
        if identity in left_blocked:
            diff.changes.append(
                SubscriptionChange(
                    ChangeType.UNDETERMINED,
                    right_object.kind,
                    right_object.ref,
                    new=right_object,
                    reason="object exists on the right but could not be read on the left",
                )
            )
        else:
            diff.changes.append(
                SubscriptionChange(ChangeType.ADDED, right_object.kind, right_object.ref, new=right_object)
            )

    return diff


def compare_repositories(
    left: CIM,
    right: CIM,
    left_source: str = "left",
    right_source: str = "right",
) -> SubscriptionDiff:
    """Extract both repositories read-only and compare their subscriptions."""

    left_snapshot = extract_subscriptions(left, left_source)
    right_snapshot = extract_subscriptions(right, source=right_source)
    return compare_snapshots(left_snapshot, right_snapshot)


def _format_value(field_value: FieldValue | None) -> str:
    if field_value is None:
        return "<absent>"
    if field_value.origin is ValueOrigin.UNINITIALIZED:
        return "<uninitialized>"
    if field_value.origin is ValueOrigin.UNRESOLVED:
        return "<unresolved>"
    prefix = "default" if field_value.origin is ValueOrigin.DEFAULT else "value"
    return f"{prefix}={field_value.value!r}"


def render_diff(diff: SubscriptionDiff) -> str:
    """Render a human-readable report with both sources for every finding."""

    lines = [
        "WMI permanent subscription comparison",
        f"  left  (before): {diff.left_source}",
        f"  right (after) : {diff.right_source}",
    ]

    titles = {
        ChangeType.ADDED: "Added subscriptions",
        ChangeType.REMOVED: "Removed subscriptions",
        ChangeType.CONTENT_CHANGED: "Consumer / filter content changes",
        ChangeType.RELATIONSHIP_CHANGED: "Binding redirects",
        ChangeType.UNDETERMINED: "Undetermined (snapshot incomplete)",
    }

    for change_type in ChangeType:
        changes = diff.changes_of_type(change_type)
        if not changes:
            continue
        lines.append("")
        lines.append(f"{titles[change_type]} ({len(changes)})")
        for change in changes:
            lines.append(f"  - [{change.kind.value}] {change.ref}")
            if change.reason:
                lines.append(f"      reason: {change.reason}")
            for field_diff in change.field_diffs:
                lines.append(f"      {field_diff.name}:")
                lines.append(f"        {diff.left_source}: {_format_value(field_diff.old)}")
                lines.append(f"        {diff.right_source}: {_format_value(field_diff.new)}")
            if change.undetermined_fields:
                joined = ", ".join(change.undetermined_fields)
                lines.append(f"      undetermined fields: {joined}")
            if change.change_type is ChangeType.RELATIONSHIP_CHANGED:
                lines.append(f"      consumer: {change.old_target} -> {change.new_target}")

    if diff.issues:
        lines.append("")
        lines.append(f"Read failures / source limitations ({len(diff.issues)})")
        for source, issue in diff.issues:
            target = f" {issue.ref}" if issue.ref else ""
            lines.append(f"  - [{source}] {issue.scope.value}{target}: {issue.detail} ({issue.error})")

    if not diff.changes and not diff.issues:
        lines.append("")
        lines.append("No semantic changes: subscriptions, field values and bindings are identical.")

    return "\n".join(lines)
