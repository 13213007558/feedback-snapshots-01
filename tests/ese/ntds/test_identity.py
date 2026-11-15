from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from dissect.database.ese.ntds.identity import (
    Change,
    ObjectIdentity,
    PathIssue,
    Snapshot,
    build_path,
    escape_rdn,
)

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS

GUID_ALICE = UUID("aaaaaaaa-0000-0000-0000-000000000001")
GUID_BOB = UUID("aaaaaaaa-0000-0000-0000-000000000002")
GUID_CAROL = UUID("aaaaaaaa-0000-0000-0000-000000000003")
GUID_DAVE = UUID("aaaaaaaa-0000-0000-0000-000000000004")
GUID_TEMP_OLD = UUID("aaaaaaaa-0000-0000-0000-000000000005")
GUID_TEMP_NEW = UUID("aaaaaaaa-0000-0000-0000-000000000006")
GUID_DOMAIN = UUID("aaaaaaaa-0000-0000-0000-000000000010")
GUID_USERS_OU = UUID("aaaaaaaa-0000-0000-0000-000000000020")
GUID_OPS_OU = UUID("aaaaaaaa-0000-0000-0000-000000000021")


def _identity(dnt: int, pdnt: int, name: str, rdn_type: str, guid: UUID, **kwargs) -> ObjectIdentity:
    return ObjectIdentity(
        dnt=dnt,
        pdnt=pdnt,
        guid=guid,
        name=name,
        names=(name,),
        rdn_type=rdn_type,
        **kwargs,
    )


@pytest.fixture(scope="module")
def snapshot_before() -> Snapshot:
    """Small snapshot with a domain, one OU and five users."""
    return Snapshot.from_identities(
        [
            _identity(10, 2, "corp", "dc", GUID_DOMAIN),
            _identity(20, 10, "users", "ou", GUID_USERS_OU),
            _identity(101, 20, "alice", "cn", GUID_ALICE),
            _identity(102, 20, "bob", "cn", GUID_BOB),
            _identity(103, 20, "carol", "cn", GUID_CAROL),
            _identity(104, 20, "dave", "cn", GUID_DAVE),
            _identity(105, 20, "temp", "cn", GUID_TEMP_OLD),
        ],
        label="before",
    )


@pytest.fixture(scope="module")
def snapshot_after() -> Snapshot:
    """Second snapshot: alice renamed, dave moved, carol removed, DNT 105 reused by a new object."""
    return Snapshot.from_identities(
        [
            _identity(10, 2, "corp", "dc", GUID_DOMAIN),
            _identity(20, 10, "users", "ou", GUID_USERS_OU),
            _identity(21, 10, "ops", "ou", GUID_OPS_OU),
            _identity(101, 20, "alice2", "cn", GUID_ALICE),
            _identity(102, 20, "bob", "cn", GUID_BOB),
            _identity(104, 21, "dave", "cn", GUID_DAVE),
            # Same DNT as the old "temp" object, but a different GUID: the DNT was reused
            _identity(105, 20, "temp2", "cn", GUID_TEMP_NEW),
        ],
        label="after",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ("Doe, John", "Doe\\, John"),
        ("a+b", "a\\+b"),
        ('say "hi"', 'say \\"hi\\"'),
        ("back\\slash", "back\\\\slash"),
        ("<angle>", "\\<angle\\>"),
        ("semi;colon", "semi\\;colon"),
        ("a=b", "a\\=b"),
        ("#hash", "\\#hash"),
        (" lead", "\\ lead"),
        ("trail ", "trail\\ "),
        ("nul\x00char", "nul\\\x00char"),
        ("", ""),
    ],
)
def test_escape_rdn(value: str, expected: str) -> None:
    """RDN values are escaped according to RFC 4514."""
    assert escape_rdn(value) == expected


def test_path_renders_escaped_segments() -> None:
    """Display paths escape RDN values and keep original case."""
    identities = {
        10: _identity(10, 2, "corp", "dc", GUID_DOMAIN),
        20: _identity(20, 10, "Doe, John", "cn", GUID_USERS_OU),
    }
    path = build_path(identities, 20)
    assert path.dn == "cn=Doe\\, John,dc=corp"
    assert path.complete


def test_path_missing_parent() -> None:
    """An incomplete parent chain yields a partial path with a diagnostic, not an exception."""
    identities = {5: _identity(5, 999, "orphan", "cn", GUID_ALICE)}
    path = build_path(identities, 5)
    assert path.issues & PathIssue.MISSING_PARENT
    assert not path.complete
    assert path.unresolved_dnt == 999
    assert path.dn == "cn=orphan,<missing:DNT=999>"


def test_path_cycle_gives_diagnostic() -> None:
    """A cyclic parent chain yields a CYCLE diagnostic instead of exhausting the recursion limit."""
    identities = {
        11: _identity(11, 12, "one", "cn", GUID_ALICE),
        12: _identity(12, 11, "two", "cn", GUID_BOB),
    }
    path = build_path(identities, 11)
    assert path.issues & PathIssue.CYCLE
    assert not path.complete
    assert path.unresolved_dnt == 11
    assert path.dn == "cn=one,cn=two,<cycle:DNT=11>"


def test_path_traces_back_to_raw_parent_chain(snapshot_after: Snapshot) -> None:
    """Every rendered path segment can be traced back to the raw identity (and parent reference)."""
    path = snapshot_after.path(104)
    assert path.dn == "cn=dave,ou=ops,dc=corp"
    assert [identity.dnt for identity in path.chain] == [104, 21, 10]
    # Each step in the chain refers to its parent by the raw PDNT
    assert path.chain[0].pdnt == path.chain[1].dnt
    assert path.chain[1].pdnt == path.chain[2].dnt


def test_phantom_and_deleted_are_preserved_not_completed() -> None:
    """Phantom and deleted objects keep their flags and are never fabricated into normal live objects."""
    phantom = ObjectIdentity(dnt=30, pdnt=999, guid=None, name=None, names=(), rdn_type=None, is_phantom=True)
    deleted = _identity(31, 2, "gone\nDEL:1234", "ou", GUID_CAROL, is_deleted=True)

    snapshot = Snapshot.from_identities([phantom, deleted])

    # The phantom stays a phantom: no name or parent is invented for it
    path = snapshot.path(30)
    assert path.issues & PathIssue.PHANTOM
    assert path.issues & PathIssue.MISSING_PARENT
    assert path.issues & PathIssue.MISSING_NAME
    assert path.dn == "<?DNT=30>,<missing:DNT=999>"

    # The deleted object renders with its tombstone name and is flagged as deleted
    path = snapshot.path(31)
    assert path.issues & PathIssue.DELETED
    assert not path.issues & PathIssue.PHANTOM
    assert path.identity.is_deleted


def test_compare_rename_move_and_dnt_reuse(snapshot_before: Snapshot, snapshot_after: Snapshot) -> None:
    """Comparing two snapshots correlates by GUID and reports DNT reuse as location-only."""
    diff = snapshot_before.compare(snapshot_after)

    by_guid = {correlation.new.guid: correlation for correlation in diff.correlated}

    # Renamed object: same GUID, different name -> correlated as RENAMED
    assert by_guid[GUID_ALICE].renamed
    assert not by_guid[GUID_ALICE].moved
    assert by_guid[GUID_ALICE].old.name == "alice"
    assert by_guid[GUID_ALICE].new.name == "alice2"

    # Unchanged object: correlated with no changes
    assert by_guid[GUID_BOB].unchanged

    # Moved object: same GUID and name, different parent reference -> correlated as MOVED
    assert by_guid[GUID_DAVE].moved
    assert not by_guid[GUID_DAVE].renamed
    assert by_guid[GUID_DAVE].changes == Change.MOVED

    # DNT reuse: the old and new object at DNT 105 share a location but are NOT correlated
    assert GUID_TEMP_OLD not in by_guid
    assert GUID_TEMP_NEW not in by_guid
    assert len(diff.collisions) == 1
    collision = diff.collisions[0]
    assert collision.old.dnt == collision.new.dnt == 105
    assert collision.old.guid == GUID_TEMP_OLD
    assert collision.new.guid == GUID_TEMP_NEW
    assert not collision.old.same_object_as(collision.new)
    assert collision.old.same_location_as(collision.new)

    # Removed: carol and the old "temp" object; added: the ops OU and the new "temp2" object
    assert {identity.dnt for identity in diff.removed} == {103, 105}
    assert {identity.dnt for identity in diff.added} == {21, 105}

    # All correlated pairs share a GUID; no correlation is based on DNT alone
    assert all(correlation.old.same_object_as(correlation.new) for correlation in diff.correlated)


def test_compare_paths_remain_traceable(snapshot_before: Snapshot, snapshot_after: Snapshot) -> None:
    """Display paths of correlated objects can be traced back to the raw parent chain in each snapshot."""
    diff = snapshot_before.compare(snapshot_after)
    renamed = next(correlation for correlation in diff.correlated if correlation.renamed)

    old_path = snapshot_before.path(renamed.old.dnt)
    new_path = snapshot_after.path(renamed.new.dnt)
    assert old_path.dn == "cn=alice,ou=users,dc=corp"
    assert new_path.dn == "cn=alice2,ou=users,dc=corp"
    assert [identity.dnt for identity in old_path.chain] == [101, 20, 10]
    assert [identity.dnt for identity in new_path.chain] == [101, 20, 10]


def test_identity_from_object(goad: NTDS) -> None:
    """Object.identity preserves record, GUID, name and parent reference separately."""
    user = next(goad.search(sAMAccountName="jon.snow"))
    identity = user.identity

    assert identity.dnt == user.dnt
    assert identity.pdnt == user.pdnt
    assert identity.guid == user.guid
    assert identity.name == "jon.snow"
    assert identity.names == ("jon.snow",)
    assert identity.rdn_type == "cn"
    assert identity.is_phantom
    assert not identity.is_deleted
    assert identity.record is user.record


def test_snapshot_from_database(goad: NTDS) -> None:
    """A database snapshot captures all objects, flagged phantoms and deleted objects included."""
    snapshot = Snapshot.from_database(goad.db, label="goad")
    assert len(snapshot) > 4000

    user = next(goad.search(sAMAccountName="jon.snow"))
    path = snapshot.path(user.dnt)
    assert path.dn == "cn=jon.snow,cn=Users,dc=north,dc=sevenkingdoms,dc=local"
    assert path.complete
    # jon.snow is a phantom in this database and must be flagged, not treated as a live local object
    assert path.issues & PathIssue.PHANTOM
    assert [identity.dnt for identity in path.chain][0] == user.dnt

    deleted = next(goad.search(sAMAccountName="robert.baratheon"))
    deleted_path = snapshot.path(deleted.dnt)
    assert deleted_path.issues & PathIssue.DELETED
    assert deleted_path.identity.is_deleted


def test_make_dn_cycle_diagnostic(goad: NTDS, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cycle in the parent chain raises a diagnostic ValueError instead of a RecursionError."""

    class FakeObject:
        def __init__(self, dnt: int, pdnt: int):
            self.dnt = dnt
            self.pdnt = pdnt

        def get(self, name: str) -> str:
            return {"RdnType": "CN", "name": f"obj{self.dnt}"}[name]

    objects = {100: FakeObject(100, 200), 200: FakeObject(200, 100)}
    monkeypatch.setattr(goad.db.data, "get", lambda dnt: objects[dnt])
    goad.db.data._make_dn.cache_clear()

    with pytest.raises(ValueError, match=r"Cycle detected in parent chain of DNT 100: 100 -> 200 -> 100"):
        goad.db.data._make_dn(100)
