"""Offline diagnostics for consistency between forward (``member``) and reverse (``memberOf``) link enumeration.

Every link record is compared individually against the raw ``link_table`` and classified as:

- ``active``: neither ``link_deactivetime`` nor ``link_deltime`` is set. Must be visible from both directions.
- ``deactivated``/``deleted``: the corresponding timestamp is set. Must be visible from neither direction.
- ``unresolved``: the link or backlink DNT has no object in the ``datatable``. Kept for investigation,
  never silently treated as a non-existent link.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dissect.database.ese.exception import KeyNotFoundError

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


class LinkEvidence(NamedTuple):
    """A single raw link record with its adopted status judgement."""

    link_dnt: int
    backlink_dnt: int
    base: int
    deactivated: bool
    deleted: bool
    link_resolvable: bool
    backlink_resolvable: bool

    @property
    def active(self) -> bool:
        return not self.deactivated and not self.deleted

    @property
    def status(self) -> str:
        if not self.link_resolvable or not self.backlink_resolvable:
            return "unresolved"
        if self.deleted:
            return "deleted"
        if self.deactivated:
            return "deactivated"
        return "active"


def collect_link_evidence(ntds: NTDS, name: str) -> list[LinkEvidence]:
    """Collect and classify all raw link records for the given link name, without dropping any record."""
    schema = ntds.db.data.schema.lookup_attribute(name=name)
    assert schema is not None and schema.link_id is not None
    base = schema.link_id // 2

    dnt_index = ntds.db.data.table.index("DNT_index")

    def resolvable(dnt: int) -> bool:
        try:
            dnt_index.search([dnt])
        except KeyNotFoundError:
            return False
        return True

    evidence = []
    for record in ntds.db.link.table.records():
        if record.get("link_base") != base:
            continue
        evidence.append(
            LinkEvidence(
                link_dnt=record.get("link_DNT"),
                backlink_dnt=record.get("backlink_DNT"),
                base=base,
                deactivated=bool(record.get("link_deactivetime")),
                deleted=bool(record.get("link_deltime")),
                link_resolvable=resolvable(record.get("link_DNT")),
                backlink_resolvable=resolvable(record.get("backlink_DNT")),
            )
        )
    return evidence


def test_member_link_base_schema(goad: NTDS) -> None:
    """The schema defines member/memberOf as an even/odd linkID pair sharing one link_base."""
    schema = goad.db.data.schema

    member = schema.lookup_attribute(name="member")
    member_of = schema.lookup_attribute(name="memberOf")

    assert member.link_id == 2
    assert member_of.link_id == 3
    assert member.link_id // 2 == member_of.link_id // 2 == 1

    base = member.link_id // 2
    assert schema.lookup_attribute(link_id=base * 2).name == "member"
    assert schema.lookup_attribute(link_id=(base * 2) + 1).name == "memberOf"


def test_deleted_link_not_reported(goad: NTDS) -> None:
    """Reproduced case: link record 3819 -> 3820 (IIS_IUSRS -> S-1-5-17) has link_deltime set.

    The raw record must remain in the link_table (evidence is preserved), but neither
    ``links()`` nor ``backlinks()`` may report it.
    """
    evidence = collect_link_evidence(goad, "member")
    deleted = [e for e in evidence if e.status == "deleted"]
    assert [(e.link_dnt, e.backlink_dnt) for e in deleted] == [(3819, 3820)]

    assert 3820 not in [obj.dnt for obj in goad.db.link.links(3819, "member")]
    assert 3819 not in [obj.dnt for obj in goad.db.link.backlinks(3820, "memberOf")]


def test_per_record_consistency(goad: NTDS) -> None:
    """Compare every raw member link record against both enumeration directions.

    Active records must appear in both directions; deleted/deactivated records in neither.
    Unresolved records are collected and reported, not silently dropped.
    """
    evidence = collect_link_evidence(goad, "member")

    forward: dict[int, set[int]] = {}
    for record in evidence:
        forward.setdefault(record.link_dnt, set())
        forward[record.link_dnt] |= {
            obj.dnt for obj in goad.db.link.links(record.link_dnt, "member")
        }

    reverse: dict[int, set[int]] = {}
    for record in evidence:
        reverse.setdefault(record.backlink_dnt, set())
        reverse[record.backlink_dnt] |= {
            obj.dnt for obj in goad.db.link.backlinks(record.backlink_dnt, "memberOf")
        }

    unresolved = []
    for record in evidence:
        if record.status == "unresolved":
            unresolved.append(record)
            continue

        if record.active:
            assert record.backlink_dnt in forward[record.link_dnt], record
            assert record.link_dnt in reverse[record.backlink_dnt], record
        else:
            assert record.backlink_dnt not in forward[record.link_dnt], record
            assert record.link_dnt not in reverse[record.backlink_dnt], record

    # The goad sample has no unresolvable link targets; if a database has any,
    # they must be surfaced here for investigation instead of being dropped.
    assert unresolved == []


def test_has_link_matches_enumeration(goad: NTDS) -> None:
    """Point lookups agree with enumeration: active records exist, deleted ones do not."""
    evidence = collect_link_evidence(goad, "member")

    for record in evidence:
        if record.status == "unresolved":
            continue

        assert goad.db.link.has_link(record.link_dnt, "member", record.backlink_dnt) is record.active
        assert goad.db.link.has_backlink(record.backlink_dnt, "memberOf", record.link_dnt) is record.active
