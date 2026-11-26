import pytest

from openfga_sdk.forensics.identifiers import (
    SubjectRegistry,
    evidence_identifier,
    public_identifier,
)


def test_public_identifier_is_stable_and_one_way():
    first = public_identifier("user:alice@internal.example.com", salt="r1")
    second = public_identifier("user:alice@internal.example.com", salt="r1")

    assert first == second
    assert first.startswith("subj_")
    assert "alice" not in first


def test_public_identifier_distinguishes_refs_and_scopes_by_salt():
    a = public_identifier("user:jordan.li@internal.example.com", salt="r1")
    b = public_identifier("user:jordan.lee@partner.example.com", salt="r1")
    a_other_salt = public_identifier("user:jordan.li@internal.example.com", salt="r2")

    assert a != b
    assert a != a_other_salt


def test_public_identifier_rejects_malformed_ref():
    with pytest.raises(ValueError):
        public_identifier("not-a-reference")


def test_evidence_identifier_stable_for_same_triple():
    triple = {"user": "user:a", "relation": "viewer", "object": "document:1"}
    other = {"user": "user:b", "relation": "viewer", "object": "document:1"}

    assert evidence_identifier(triple) == evidence_identifier(dict(triple))
    assert evidence_identifier(triple) != evidence_identifier(other)


def test_registry_reuses_id_for_repeated_ref():
    registry = SubjectRegistry(salt="r1")

    assert registry.public_id("user:alice@internal.example.com") == registry.public_id(
        "user:alice@internal.example.com"
    )
    assert len(registry.raw_mapping()) == 1


def test_registry_keeps_distinct_subjects_with_same_display_name():
    registry = SubjectRegistry(
        salt="r1",
        display_name_resolver=lambda ref: "Jordan Lee",
    )

    internal = registry.public_id("user:jordan.li@internal.example.com")
    external = registry.public_id("user:jordan.lee@partner.example.com")

    assert internal != external
    collisions = registry.display_name_collisions()
    assert len(collisions) == 1
    assert collisions[0]["display_name"] == "Jordan Lee"
    assert collisions[0]["public_subject_ids"] == sorted([internal, external])

    records = {item["public_subject_id"]: item for item in registry.public_records()}
    assert records[internal]["display_names"] == ["Jordan Lee"]
    assert records[external]["display_names"] == ["Jordan Lee"]


def test_registry_does_not_merge_on_display_name_without_resolver():
    registry = SubjectRegistry(salt="r1")
    registry.record_display_name("user:a", "Same Name")
    registry.record_display_name("user:b", "Same Name")

    assert registry.public_id("user:a") != registry.public_id("user:b")
    assert len(registry.display_name_collisions()) == 1
