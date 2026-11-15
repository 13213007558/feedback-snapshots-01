from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from dissect.database.ese.ntds.identity import NTDSObjectSource, ObjectState, PathIssueKind

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_source_returns_identity_for_every_record(goad: NTDS) -> None:
    source = NTDSObjectSource(goad.db)
    identities = list(source.identities())

    assert identities
    for identity in identities:
        assert isinstance(identity.dnt, int)
        assert identity.guid is None or isinstance(identity.guid, UUID)
        # DNT is the in-database locator and must match the underlying row.
        assert source.get_identity(identity.dnt).dnt == identity.dnt


def test_missing_dnt_resolves_to_none(goad: NTDS) -> None:
    source = NTDSObjectSource(goad.db)
    assert source.get_identity(99_999_999) is None


def test_deleted_and_phantom_keep_their_state(goad: NTDS) -> None:
    source = NTDSObjectSource(goad.db)
    states = {identity.state for identity in source.identities()}

    assert ObjectState.DELETED in states
    # The GOAD snapshot contains phantom rows for the held naming contexts.
    assert ObjectState.PHANTOM in states
    for identity in source.identities():
        if identity.state in (ObjectState.DELETED, ObjectState.PHANTOM):
            assert not identity.is_live


def test_object_identity_view_and_display_path(goad: NTDS) -> None:
    admin = next(obj for obj in goad.db.data.iter() if obj.name and obj.name.upper() == "ADMINISTRATOR")

    identity = admin.identity
    assert identity.dnt == admin.dnt
    assert identity.pdnt == admin.pdnt
    assert identity.guid == UUID(str(admin.guid))

    path = admin.display_path()
    assert path.is_complete
    assert path.retraces()
    assert str(admin.distinguished_name).lower() == path.dn.lower()
    assert not any(issue.kind == PathIssueKind.CYCLE for issue in path.issues)


def test_tombstone_display_path_has_no_raw_control_characters(goad: NTDS) -> None:
    tombstone = next(obj for obj in goad.db.data.iter() if obj.is_deleted and obj.name and "DEL:" in obj.name)
    path = tombstone.display_path()

    assert path.retraces()
    assert all(ord(char) >= 0x20 and ord(char) != 0x7F for char in path.dn)
    assert "\\0A" in path.dn
