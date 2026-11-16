from __future__ import annotations

from typing import BinaryIO

from dissect.cim.cim import CIM
from dissect.cim.subscription import (
    ObjectKind,
    ValueOrigin,
    compare_snapshots,
    extract_subscriptions,
)


def test_cim(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    assert repo

    subscription_ns = repo.root.namespace("subscription")
    binding = next(subscription_ns.class_("__filtertoconsumerbinding").instances)
    consumer = subscription_ns.query(binding.properties["Consumer"].value)
    assert consumer.properties["SourceName"].value == "Service Control Manager"


def test_subscription_extraction_and_self_comparison(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]
) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    snapshot = extract_subscriptions(repo, "test-repo")

    assert snapshot.issues == []
    kinds = {obj.kind for obj in snapshot.objects.values()}
    assert kinds == {ObjectKind.FILTER, ObjectKind.CONSUMER, ObjectKind.BINDING}

    consumer = next(obj for obj in snapshot.objects.values() if obj.kind is ObjectKind.CONSUMER)
    assert consumer.fields["SourceName"].origin is ValueOrigin.EXPLICIT
    assert consumer.fields["SourceName"].value == "Service Control Manager"
    assert consumer.fields["EventID"].origin is ValueOrigin.DEFAULT
    assert consumer.fields["MachineName"].origin is ValueOrigin.UNINITIALIZED

    binding = next(obj for obj in snapshot.objects.values() if obj.kind is ObjectKind.BINDING)
    assert binding.consumer_ref is not None
    assert binding.consumer_ref.namespace.lower() == consumer.ref.namespace.lower()
    assert binding.consumer_ref.class_name.lower() == consumer.ref.class_name.lower()

    # Re-extracting the same repository must never report a semantic change,
    # regardless of physical page or index layout.
    repo_again = CIM(index_bin, objects_bin, mappings_bin)
    diff = compare_snapshots(snapshot, extract_subscriptions(repo_again, "test-repo-copy"))
    assert diff.has_semantic_changes is False
    assert diff.changes == []
