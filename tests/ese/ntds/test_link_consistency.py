"""Offline diagnosis of group->member vs user->memberOf consistency within a single NTDS.dit.

Evidence model (per link_table record):

- Schema: ``member`` has linkID 2 (forward link), ``memberOf`` has linkID 3 (backlink).
  Both share ``link_base = linkID // 2 = 1``, so both directions read the same records.
- State judgment: a link record is ACTIVE iff ``link_deltime`` and ``link_deactivetime``
  are both 0/NULL. A record with either set is a tombstone of a deleted/deactivated
  linked value and must not be reported as a live membership.
- Endpoint judgment: each DNT is resolved against the datatable DNT_index. A DNT that
  does not resolve is MISSING (kept as an unresolved relation, never treated as an
  absent link); a resolved object is LOCAL or PHANTOM (cross-domain stub, not
  queryable through the object API by design).

Run ``python -m tests.ese.ntds.test_link_consistency`` from the repository root to print
the per-record comparison table for the GOAD fixture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

import pytest

from dissect.database.ese.exception import KeyNotFoundError

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


class LinkEvidence(NamedTuple):
    """Evidence for a single link_table record."""

    link_dnt: int
    backlink_dnt: int
    link_base: int
    active: bool
    deltime: int | None
    deactivetime: int | None
    source: str  # LOCAL / PHANTOM / MISSING
    target: str  # LOCAL / PHANTOM / MISSING
    visible_forward: bool  # visible via LinkTable.links() from link_dnt
    visible_backward: bool  # visible via LinkTable.backlinks() from backlink_dnt

    @property
    def unresolved(self) -> bool:
        """Whether either endpoint could not be fully resolved locally."""
        return self.source != "LOCAL" or self.target != "LOCAL"


def _classify_dnt(ntds: NTDS, dnt: int) -> str:
    try:
        obj = ntds.db.data.get(dnt)
    except KeyNotFoundError:
        return "MISSING"
    return "PHANTOM" if obj.is_phantom else "LOCAL"


def collect_link_evidence(ntds: NTDS, link_name: str = "member") -> list[LinkEvidence]:
    """Collect per-record evidence for all records of the given link (default: member/memberOf)."""
    db = ntds.db
    base = db.link._link_base(link_name)

    evidence = []
    for record in db.link.table.records():
        if record.get("link_base") != base:
            continue

        link_dnt = record.get("link_DNT")
        backlink_dnt = record.get("backlink_DNT")
        evidence.append(
            LinkEvidence(
                link_dnt=link_dnt,
                backlink_dnt=backlink_dnt,
                link_base=base,
                active=db.link._is_active(record),
                deltime=record.get("link_deltime"),
                deactivetime=record.get("link_deactivetime"),
                source=_classify_dnt(ntds, link_dnt),
                target=_classify_dnt(ntds, backlink_dnt),
                visible_forward=db.link.has_link(link_dnt, link_name, backlink_dnt),
                visible_backward=db.link.has_backlink(backlink_dnt, "memberOf", link_dnt),
            )
        )
    return evidence


def test_member_link_schema(goad: NTDS) -> None:
    """member and memberOf are forward/backward halves of the same link_base."""
    schema = goad.db.data.schema
    member = schema.lookup_attribute(name="member")
    memberof = schema.lookup_attribute(name="memberOf")

    assert member.link_id == 2
    assert memberof.link_id == 3
    assert member.link_id // 2 == memberof.link_id // 2 == 1
    assert goad.db.link._link_base("member") == goad.db.link._link_base("memberOf") == 1


def test_tombstoned_link_record_present(goad: NTDS) -> None:
    """The GOAD fixture contains exactly one tombstoned member link: IIS_IUSRS -> S-1-5-17.

    Source record: link_DNT=3819, backlink_DNT=3820, link_base=1, link_deltime=13410556070.
    Both endpoint objects exist and are LOCAL, so the tombstone state on the link record
    itself is the only reason this membership must not be reported.
    """
    evidence = collect_link_evidence(goad)
    tombstoned = [e for e in evidence if not e.active]

    assert len(tombstoned) == 1
    (tombstone,) = tombstoned
    assert tombstone.link_dnt == 3819
    assert tombstone.backlink_dnt == 3820
    assert tombstone.deltime == 13410556070
    assert tombstone.source == "LOCAL"
    assert tombstone.target == "LOCAL"

    assert goad.db.data.get(3819).name == "IIS_IUSRS"
    assert goad.db.data.get(3820).name == "S-1-5-17"


def test_tombstoned_link_not_reported(goad: NTDS) -> None:
    """A tombstoned link must be invisible from both directions and both check APIs."""
    db = goad.db

    assert 3820 not in [obj.dnt for obj in db.link.links(3819, "member")]
    assert 3819 not in [obj.dnt for obj in db.link.backlinks(3820, "memberOf")]
    assert not db.link.has_link(3819, "member", 3820)
    assert not db.link.has_backlink(3820, "memberOf", 3819)

    group = db.data.get(3819)
    assert 3820 not in [member.dnt for member in group.members()]

    # Active links remain visible through the same APIs
    assert db.link.has_link(3806, "member", 3802)
    assert db.link.has_backlink(3802, "memberOf", 3806)
    assert 3802 in [obj.dnt for obj in db.link.links(3806, "member")]


def test_active_links_symmetric(goad: NTDS) -> None:
    """Every active link record is visible from both directions; every tombstone from neither."""
    for e in collect_link_evidence(goad):
        assert e.visible_forward == e.active, f"forward visibility mismatch: {e}"
        assert e.visible_backward == e.active, f"backward visibility mismatch: {e}"


def test_unresolved_relations_kept(goad: NTDS) -> None:
    """Phantom or missing endpoints are reported as unresolved, never silently dropped.

    In the GOAD fixture all member/memberOf endpoints resolve to LOCAL objects, but
    phantom objects exist elsewhere in the database: querying links from a phantom
    object raises by design, and the diagnostic keeps such relations for investigation.
    """
    evidence = collect_link_evidence(goad)
    assert evidence, "expected member link records in the GOAD fixture"
    assert not [e for e in evidence if e.unresolved]
    assert not [e for e in evidence if e.source == "MISSING" or e.target == "MISSING"]

    # Phantom objects are guarded at the object API level; the relation stays unresolved
    phantom_user = next(u for u in goad.users() if u.is_phantom)
    with pytest.raises(ValueError, match="phantom"):
        list(phantom_user.groups())


def main() -> None:
    from dissect.database.ese.ntds.ntds import NTDS
    from tests._util import open_file_gz

    for fh in open_file_gz("_data/ese/ntds/goad/ntds.dit.gz"):
        ntds = NTDS(fh)

        print(
            f"{'link_DNT':>8} {'backlink_DNT':>12} {'state':<10} {'deltime':<12} "
            f"{'src':<8} {'dst':<8} {'fwd':<4} {'bwd':<4}"
        )
        for e in collect_link_evidence(ntds):
            state = "ACTIVE" if e.active else "TOMBSTONE"
            print(
                f"{e.link_dnt:>8} {e.backlink_dnt:>12} {state:<10} {str(e.deltime):<12} "
                f"{e.source:<8} {e.target:<8} {str(e.visible_forward):<4} {str(e.visible_backward):<4}"
            )


if __name__ == "__main__":
    main()
