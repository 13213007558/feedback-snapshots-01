from __future__ import annotations

from uuid import UUID

from dissect.database.ese.ntds.identity import (
    RelationKind,
    Snapshot,
    compare_snapshots,
    render_comparison,
)
from tests.ese.ntds.identity.conftest import (
    GUID_ALICE,
    GUID_BOB,
    GUID_CAROL,
    GUID_DAVE,
    GUID_EVE,
    GUID_SERVICE_NEW,
    GUID_TOMBSTONE,
)


def test_relation_kind_counts(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    comparison = compare_snapshots(old, new)

    assert {kind: len(comparison.of_kind(kind)) for kind in RelationKind if comparison.of_kind(kind)} == {
        RelationKind.SAME: 5,
        RelationKind.RENAMED: 1,
        RelationKind.MOVED: 1,
        RelationKind.DNT_REUSED: 1,
        RelationKind.POSITION_ONLY: 1,
        RelationKind.DISAPPEARED: 1,
        RelationKind.APPEARED: 1,
    }


def test_rename_is_correlated_by_guid(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    relation = compare_snapshots(old, new).of_kind(RelationKind.RENAMED)[0]

    assert relation.old is not None
    assert relation.new is not None
    assert relation.old.guid == UUID(GUID_ALICE)
    assert relation.new.guid == UUID(GUID_ALICE)
    assert relation.old.dnt == relation.new.dnt == 300
    assert relation.old.name == "alice.old"
    assert relation.new.name == "alice.new"
    assert relation.old_path.dn.startswith("cn=alice.old,")
    assert relation.new_path.dn.startswith("cn=alice.new,")


def test_move_is_correlated_by_guid_across_dnts(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    relation = compare_snapshots(old, new).of_kind(RelationKind.MOVED)[0]

    assert relation.old.guid == relation.new.guid == UUID(GUID_BOB)
    assert (relation.old.dnt, relation.new.dnt) == (301, 401)
    assert (relation.old.pdnt, relation.new.pdnt) == (102, 110)
    assert relation.old_path.dn.startswith("cn=bob,cn=Users,")
    assert relation.new_path.dn.startswith("cn=bob,ou=Staff,")


def test_reused_dnt_is_not_treated_as_same_object(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    relation = compare_snapshots(old, new).of_kind(RelationKind.DNT_REUSED)[0]

    assert relation.old.dnt == relation.new.dnt == 305
    assert relation.old.guid == UUID(GUID_CAROL)
    assert relation.new.guid == UUID(GUID_DAVE)
    assert relation.old.guid != relation.new.guid
    # Both sides of the reused slot remain independently addressable by display path.
    assert relation.old_path.dn.startswith("cn=carol,")
    assert relation.new_path.dn.startswith("cn=dave,")


def test_position_only_match_is_separate_from_identity(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    relation = compare_snapshots(old, new).of_kind(RelationKind.POSITION_ONLY)[0]

    assert relation.old.guid == UUID(GUID_EVE)
    assert relation.new.guid == UUID(GUID_SERVICE_NEW)
    assert relation.old_path.dn == relation.new_path.dn
    assert relation.old_path.dn.startswith("cn=service-acct,")


def test_carol_and_dave_are_appear_disappear_not_a_rename(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    comparison = compare_snapshots(old, new)

    disappeared = {relation.old.guid for relation in comparison.of_kind(RelationKind.DISAPPEARED)}
    appeared = {relation.new.guid for relation in comparison.of_kind(RelationKind.APPEARED)}
    assert disappeared == {UUID(GUID_EVE)}
    assert appeared == {UUID(GUID_SERVICE_NEW)}


def test_deleted_object_is_never_promoted_to_live(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    comparison = compare_snapshots(old, new)

    same = comparison.of_kind(RelationKind.SAME)
    tombstone = next(relation for relation in same if relation.old.guid == UUID(GUID_TOMBSTONE))
    assert tombstone.old.state.name == "DELETED"
    assert tombstone.new.state.name == "DELETED"
    assert not tombstone.old.is_live
    assert not tombstone.new.is_live
    # The embedded newline is escaped on both rendered paths.
    assert "\\0A" in tombstone.old_path.dn
    assert "\n" not in tombstone.old_path.dn


def test_every_display_path_retraces_the_parent_chain(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    for relation in compare_snapshots(old, new):
        for path in (relation.old_path, relation.new_path):
            if path is not None:
                assert path.retraces(), path


def test_rendered_report_documents_correlations(snapshot_pair: tuple[Snapshot, Snapshot]) -> None:
    old, new = snapshot_pair
    report = render_comparison(compare_snapshots(old, new))

    assert "snapshot-A -> snapshot-B" in report
    assert "Renamed objects" in report
    assert "Reused DNT slots" in report
    assert "Position-only matches" in report
