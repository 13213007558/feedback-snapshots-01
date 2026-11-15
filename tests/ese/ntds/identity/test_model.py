from __future__ import annotations

from uuid import UUID

from dissect.database.ese.ntds.identity import (
    ObjectState,
    RelationKind,
    Snapshot,
    compare_snapshots,
    identity_from_mapping,
)


def test_identity_keeps_fields_separate() -> None:
    identity = identity_from_mapping(
        {
            "dnt": 7,
            "pdnt": 3,
            "guid": "12345678-1234-1234-1234-123456789abc",
            "name": "obj",
            "rdn_type": "cn",
            "ncdnt": 2,
        }
    )

    assert identity.dnt == 7
    assert identity.pdnt == 3
    assert identity.guid == UUID("12345678-1234-1234-1234-123456789abc")
    assert identity.name == "obj"
    assert identity.rdn_type == "cn"
    assert identity.ncdnt == 2
    assert identity.is_live


def test_missing_values_are_not_fabricated() -> None:
    identity = identity_from_mapping({"dnt": 9, "pdnt": None})

    assert identity.pdnt is None
    assert identity.guid is None
    assert identity.name is None
    assert identity.rdn_type is None
    assert not identity.has_rdn


def test_state_change_is_classified_separately_from_rename() -> None:
    guid = "abcdef00-0000-0000-0000-000000000001"
    records = [
        {"dnt": 2, "pdnt": 0, "name": "$ROOT_OBJECT$"},
        {"dnt": 5, "pdnt": 2, "guid": guid, "name": "x", "rdn_type": "cn"},
    ]
    old = Snapshot.from_mappings(records, label="old")
    new = Snapshot.from_mappings(
        [
            {"dnt": 2, "pdnt": 0, "name": "$ROOT_OBJECT$"},
            {"dnt": 5, "pdnt": 2, "guid": guid, "name": "x", "rdn_type": "cn", "is_deleted": True},
        ],
        label="new",
    )

    relations = compare_snapshots(old, new)
    state_changes = relations.of_kind(RelationKind.STATE_CHANGED)
    assert len(state_changes) == 1
    assert state_changes[0].old.state == ObjectState.LIVE
    assert state_changes[0].new.state == ObjectState.DELETED
