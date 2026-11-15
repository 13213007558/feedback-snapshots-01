from __future__ import annotations

import pytest

from dissect.database.ese.ntds.identity import Snapshot

# Stable GUIDs for the two-snapshot scenario.
GUID_LOCAL = "00000000-0000-0000-0000-000000000001"
GUID_EXAMPLE = "00000000-0000-0000-0000-000000000010"
GUID_USERS = "00000000-0000-0000-0000-000000000002"
GUID_STAFF = "00000000-0000-0000-0000-000000000011"
GUID_ALICE = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GUID_BOB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GUID_CAROL = "cccccccc-cccc-cccc-cccc-cccccccccccc"
GUID_DAVE = "dddddddd-dddd-dddd-dddd-dddddddddddd"
GUID_EVE = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
GUID_SERVICE_NEW = "11111111-2222-3333-4444-555555555555"
GUID_TOMBSTONE = "ffffffff-ffff-ffff-ffff-ffffffffffff"


def _skeleton() -> list[dict]:
    return [
        {"dnt": 2, "pdnt": 0, "name": "$ROOT_OBJECT$"},
        {"dnt": 100, "pdnt": 2, "guid": GUID_LOCAL, "name": "local", "rdn_type": "dc"},
        {"dnt": 101, "pdnt": 100, "guid": GUID_EXAMPLE, "name": "example", "rdn_type": "dc"},
        {"dnt": 102, "pdnt": 101, "guid": GUID_USERS, "name": "Users", "rdn_type": "cn"},
        {"dnt": 110, "pdnt": 101, "guid": GUID_STAFF, "name": "Staff", "rdn_type": "ou"},
    ]


def _tombstone() -> dict:
    return {
        "dnt": 307,
        "pdnt": 102,
        "guid": GUID_TOMBSTONE,
        "name": "ghost\nDEL:ffffffff-ffff-ffff-ffff-ffffffffffff",
        "rdn_type": "cn",
        "is_deleted": True,
    }


@pytest.fixture()
def snapshot_pair() -> tuple[Snapshot, Snapshot]:
    """Two small snapshots exercising rename, move, reuse, position-only and deletion."""
    old_records = [
        *_skeleton(),
        *(
            # Alice is renamed between snapshots but keeps GUID and DNT.
            {"dnt": 300, "pdnt": 102, "guid": GUID_ALICE, "name": "alice.old", "rdn_type": "cn"},
            # Bob keeps his GUID but moves from Users to Staff (DNT changes as well).
            {"dnt": 301, "pdnt": 102, "guid": GUID_BOB, "name": "bob", "rdn_type": "cn"},
            # Carol occupies DNT 305 in the old snapshot.
            {"dnt": 305, "pdnt": 102, "guid": GUID_CAROL, "name": "carol", "rdn_type": "cn"},
            # Eve holds the service-acct path, later occupied by an unrelated object.
            {"dnt": 306, "pdnt": 102, "guid": GUID_EVE, "name": "service-acct", "rdn_type": "cn"},
            _tombstone(),
        ),
    ]
    new_records = [
        *_skeleton(),
        *(
            {"dnt": 300, "pdnt": 102, "guid": GUID_ALICE, "name": "alice.new", "rdn_type": "cn"},
            {"dnt": 401, "pdnt": 110, "guid": GUID_BOB, "name": "bob", "rdn_type": "cn"},
            # DNT 305 is reused by Dave, a brand new object with a different GUID.
            {"dnt": 305, "pdnt": 102, "guid": GUID_DAVE, "name": "dave", "rdn_type": "cn"},
            {"dnt": 406, "pdnt": 102, "guid": GUID_SERVICE_NEW, "name": "service-acct", "rdn_type": "cn"},
            _tombstone(),
        ),
    ]
    return (
        Snapshot.from_mappings(old_records, label="snapshot-A"),
        Snapshot.from_mappings(new_records, label="snapshot-B"),
    )
