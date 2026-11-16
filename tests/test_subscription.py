from __future__ import annotations

from dissect.cim.subscription import (
    BINDING_CLASS,
    ChangeType,
    ExtractionIssue,
    FieldValue,
    IssueScope,
    ObjectKind,
    ObjectRef,
    SubscriptionObject,
    SubscriptionSnapshot,
    ValueOrigin,
    compare_snapshots,
    parse_reference,
    render_diff,
)

NS = "root\\subscription"


def fv(origin: ValueOrigin, value: object = None) -> FieldValue:
    return FieldValue(origin, value)


def make_object(
    class_name: str,
    key: str,
    kind: ObjectKind,
    fields: dict[str, FieldValue] | None = None,
    filter_ref: ObjectRef | None = None,
    consumer_ref: ObjectRef | None = None,
    namespace: str = NS,
) -> SubscriptionObject:
    ref = ObjectRef(namespace, class_name, key)
    return SubscriptionObject(ref, kind, dict(fields or {}), filter_ref, consumer_ref)


def filter_obj(name: str, query: str = "SELECT * FROM __InstanceModificationEvent") -> SubscriptionObject:
    return make_object(
        "__EventFilter",
        f'Name="{name}"',
        ObjectKind.FILTER,
        {"Name": fv(ValueOrigin.EXPLICIT, name), "Query": fv(ValueOrigin.EXPLICIT, query)},
    )


def consumer_obj(class_name: str, name: str, command: str | None = None, namespace: str = NS) -> SubscriptionObject:
    fields = {
        "Name": fv(ValueOrigin.EXPLICIT, name),
        # A class default and an explicit value must never compare as equal even
        # when their effective values coincide.
        "EventID": fv(ValueOrigin.DEFAULT, 0),
    }
    if class_name == "CommandLineEventConsumer":
        fields["CommandLineTemplate"] = fv(ValueOrigin.EXPLICIT, command)
    return make_object(class_name, f'Name="{name}"', ObjectKind.CONSUMER, fields, namespace=namespace)


def binding_obj(name: str, filter_name: str, consumer: ObjectRef) -> SubscriptionObject:
    ref = ObjectRef(NS, BINDING_CLASS, f'Name="{name}"')
    filter_ref = ObjectRef(NS, "__EventFilter", f'Name="{filter_name}"')
    return SubscriptionObject(
        ref,
        ObjectKind.BINDING,
        {
            "Name": fv(ValueOrigin.EXPLICIT, name),
            "Filter": fv(ValueOrigin.EXPLICIT, f'__EventFilter.Name="{filter_name}"'),
            "Consumer": fv(ValueOrigin.EXPLICIT, f'{consumer.class_name}.Name="{consumer.key}"'),
        },
        filter_ref,
        consumer,
        raw_filter=f'__EventFilter.Name="{filter_name}"',
        raw_consumer=f"{consumer.class_name}.{consumer.key}",
    )


def base_chain() -> tuple[SubscriptionObject, SubscriptionObject, SubscriptionObject]:
    flt = filter_obj("PersistenceFilter")
    consumer = consumer_obj("CommandLineEventConsumer", "PersistenceConsumer", "powershell -ep bypass old.ps1")
    binding = binding_obj("PersistenceBinding", "PersistenceFilter", consumer.ref)
    return flt, consumer, binding


def snapshot(source: str, objects: list[SubscriptionObject], issues: list[ExtractionIssue] | None = None):
    snap = SubscriptionSnapshot(source, issues=list(issues or []))
    for obj in objects:
        snap.objects[obj.ref.identity] = obj
    return snap


def test_pure_page_reorder_is_not_a_semantic_change() -> None:
    flt, consumer, binding = base_chain()
    # Insertion order and (in a real repo) physical pages / index positions may
    # differ, but the semantic identities and values are identical.
    left = snapshot("before", [flt, consumer, binding])
    right = snapshot("after", [binding, flt, consumer])

    diff = compare_snapshots(left, right)

    assert diff.has_semantic_changes is False
    assert diff.changes == []
    report = render_diff(diff)
    assert "No semantic changes" in report
    assert report.index("before") < report.index("after")


def test_command_text_change_is_a_content_change() -> None:
    left_filter, left_consumer, left_binding = base_chain()
    right_filter, right_consumer, right_binding = base_chain()
    right_consumer.fields["CommandLineTemplate"] = fv(ValueOrigin.EXPLICIT, "powershell -ep bypass new.ps1")

    diff = compare_snapshots(
        snapshot("before", [left_filter, left_consumer, left_binding]),
        snapshot("after", [right_filter, right_consumer, right_binding]),
    )

    assert diff.has_semantic_changes is True
    content = diff.changes_of_type(ChangeType.CONTENT_CHANGED)
    assert len(content) == 1
    change = content[0]
    assert change.kind is ObjectKind.CONSUMER
    field_names = [field_diff.name for field_diff in change.field_diffs]
    assert field_names == ["CommandLineTemplate"]
    old = change.field_diffs[0].old
    new = change.field_diffs[0].new
    assert old.value == "powershell -ep bypass old.ps1"
    assert new.value == "powershell -ep bypass new.ps1"
    assert old.origin is ValueOrigin.EXPLICIT
    assert new.origin is ValueOrigin.EXPLICIT

    report = render_diff(diff)
    assert "content changes" in report
    assert "before" in report
    assert "after" in report
    assert "old.ps1" in report
    assert "new.ps1" in report


def test_binding_redirect_is_a_relationship_change() -> None:
    left_filter, left_consumer, left_binding = base_chain()
    other_consumer = consumer_obj("CommandLineEventConsumer", "OtherConsumer", "whoami")

    right_filter = filter_obj("PersistenceFilter")
    right_consumer = left_consumer
    right_binding = binding_obj("PersistenceBinding", "PersistenceFilter", other_consumer.ref)

    diff = compare_snapshots(
        snapshot("before", [left_filter, left_consumer, left_binding]),
        snapshot("after", [right_filter, right_consumer, right_binding, other_consumer]),
    )

    redirects = diff.changes_of_type(ChangeType.RELATIONSHIP_CHANGED)
    assert len(redirects) == 1
    change = redirects[0]
    assert change.kind is ObjectKind.BINDING
    assert change.old_target == left_consumer.ref
    assert change.new_target == other_consumer.ref
    # The redirect itself is reported even though the binding's other fields did
    # not change.
    assert change.field_diffs == []

    report = render_diff(diff)
    assert "Binding redirects" in report
    assert "PersistenceConsumer" in report
    assert "OtherConsumer" in report


def test_same_name_in_different_namespace_is_not_merged() -> None:
    left = consumer_obj("CommandLineEventConsumer", "Dup", "a")
    right = consumer_obj("CommandLineEventConsumer", "Dup", "b", namespace="root\\other")

    diff = compare_snapshots(snapshot("before", [left]), snapshot("after", [right]))

    types = {change.change_type for change in diff.changes}
    assert ChangeType.ADDED in types
    assert ChangeType.REMOVED in types
    assert ChangeType.CONTENT_CHANGED not in types


def test_redirect_detected_even_when_references_unresolvable() -> None:
    ref = ObjectRef(NS, BINDING_CLASS, 'Name="B"')
    base_fields = {
        "Name": fv(ValueOrigin.EXPLICIT, "B"),
        "Filter": fv(ValueOrigin.EXPLICIT, "garbage-filter-ref"),
    }
    left = SubscriptionObject(
        ref,
        ObjectKind.BINDING,
        {**base_fields, "Consumer": fv(ValueOrigin.EXPLICIT, "garbage://old")},
        None,
        None,
        raw_filter="garbage-filter-ref",
        raw_consumer="garbage://old",
    )
    right = SubscriptionObject(
        ref,
        ObjectKind.BINDING,
        {**base_fields, "Consumer": fv(ValueOrigin.EXPLICIT, "garbage://new")},
        None,
        None,
        raw_filter="garbage-filter-ref",
        raw_consumer="garbage://new",
    )

    diff = compare_snapshots(snapshot("before", [left]), snapshot("after", [right]))
    (change,) = diff.changes
    assert change.change_type is ChangeType.RELATIONSHIP_CHANGED
    assert change.field_diffs == []


def test_default_explicit_and_unresolved_are_distinct() -> None:
    # Same effective value 0, different origin -> content change.
    left = consumer_obj("CommandLineEventConsumer", "C", "x")
    right = consumer_obj("CommandLineEventConsumer", "C", "x")
    right.fields["EventID"] = fv(ValueOrigin.EXPLICIT, 0)

    diff = compare_snapshots(snapshot("before", [left]), snapshot("after", [right]))
    (change,) = diff.changes_of_type(ChangeType.CONTENT_CHANGED)
    assert [field_diff.name for field_diff in change.field_diffs] == ["EventID"]

    # Unresolved on one side cannot be claimed as a change.
    broken = consumer_obj("CommandLineEventConsumer", "C", "x")
    broken.fields["EventID"] = fv(ValueOrigin.UNRESOLVED)
    diff2 = compare_snapshots(snapshot("before", [left]), snapshot("after", [broken]))
    (undetermined,) = diff2.changes
    assert undetermined.change_type is ChangeType.UNDETERMINED
    assert undetermined.undetermined_fields == ["EventID"]


def test_read_failure_is_not_reported_as_removal() -> None:
    flt, consumer, binding = base_chain()
    left = snapshot("before", [flt, consumer, binding])

    # The right snapshot lost the consumer object and recorded a read failure
    # for the same identity, so removal cannot be proven.
    issue = ExtractionIssue(IssueScope.OBJECT, "unreadable page", "UnmappedPageError(...)", consumer.ref)
    right = snapshot("after", [flt, binding], issues=[issue])

    diff = compare_snapshots(left, right)
    assert diff.changes_of_type(ChangeType.REMOVED) == []
    undetermined = diff.changes_of_type(ChangeType.UNDETERMINED)
    assert len(undetermined) == 1
    assert undetermined[0].ref == consumer.ref

    report = render_diff(diff)
    assert "Undetermined" in report
    assert "Read failures" in report
    assert "after" in report


def test_added_and_removed_objects() -> None:
    flt, consumer, binding = base_chain()
    extra = consumer_obj("NTEventLogEventConsumer", "Extra")

    diff = compare_snapshots(
        snapshot("before", [flt, consumer, binding]),
        snapshot("after", [flt, binding, extra]),
    )
    added = diff.changes_of_type(ChangeType.ADDED)
    removed = diff.changes_of_type(ChangeType.REMOVED)
    assert [change.ref for change in added] == [extra.ref]
    assert [change.ref for change in removed] == [consumer.ref]


def test_parse_reference_variants() -> None:
    assert parse_reference('Cmd.Name="x"', NS) == ObjectRef(NS, "Cmd", 'Name="x"')
    assert parse_reference("root/sub:Cmd.Name='x'", NS) == ObjectRef("root\\sub", "Cmd", 'Name="x"')
    assert parse_reference("//./root/sub:Cmd.A='1',B='2'", NS) == ObjectRef("root\\sub", "Cmd", 'A="1",B="2"')
