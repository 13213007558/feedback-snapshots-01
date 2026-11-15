from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.membership import (
    EdgeKind,
    MembershipTracer,
    PathStatus,
    UnresolvedReason,
)
from dissect.database.ese.ntds.util import sid_domain

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.membership import MembershipTrace

LOCAL_DOMAIN_SID = "S-1-5-21-100-200-300"
FOREIGN_DOMAIN_SID = "S-1-5-21-999-888-777"
OTHER_FOREIGN_DOMAIN_SID = "S-1-5-21-555-666-777"


class FakeRecord:
    """Minimal stand-in for an ESE link_table record."""

    def __init__(self, **values: Any):
        self.values = values

    def get(self, name: str, raw: bool = False) -> Any:
        return self.values.get(name)


class FakeObject:
    """Minimal stand-in for an NTDS object, exposing only the attributes used by the tracer."""

    def __init__(
        self,
        dnt: int,
        dn: str,
        sid: str | None,
        object_class: list[str],
        *,
        name: str | None = None,
        primary_group_id: int | None = None,
        is_phantom: bool = False,
    ):
        self.dnt = dnt
        self.dn = dn
        self.sid = sid
        self.object_class = object_class
        self.name = name or dn
        self.primary_group_id = primary_group_id
        self.is_phantom = is_phantom

    def get(self, name: str) -> Any:
        if name == "primaryGroupID":
            return self.primary_group_id
        if name == "objectSid":
            return self.sid
        raise KeyError(name)

    def __repr__(self) -> str:
        return f"<FakeObject {self.dn}>"


class FakeData:
    """Small in-memory substitute for DataTable."""

    def __init__(self, objects: list[FakeObject]):
        self.objects = objects
        self.by_dnt = {obj.dnt: obj for obj in objects}

    def iter(self) -> Iterator[FakeObject]:
        yield from self.objects

    def get(self, dnt: int) -> FakeObject:
        if dnt not in self.by_dnt:
            raise KeyNotFoundError(dnt)
        return self.by_dnt[dnt]

    def search(self, **kwargs: Any) -> Iterator[FakeObject]:
        ((key, value),) = kwargs.items()
        for obj in self.objects:
            if (key == "objectSid" and obj.sid == value) or (
                key == "primaryGroupID" and obj.primary_group_id == value
            ):
                yield obj

    def lookup(self, **kwargs: Any) -> FakeObject:
        if (obj := next(self.search(**kwargs), None)) is None:
            raise KeyNotFoundError(kwargs)
        return obj


class FakeLinkTable:
    """Small in-memory substitute for LinkTable containing raw member link records."""

    def __init__(self, records: list[tuple[int, int, FakeRecord]]):
        self.records = records

    def link_records(self, name: str | None = None) -> Iterator[tuple[int, int, FakeRecord]]:
        assert name in (None, "member")
        yield from self.records


class FakeDatabase:
    """Small NTDS database fixture with just enough surface for offline membership tracing."""

    def __init__(self, objects: list[FakeObject], records: list[tuple[int, int, FakeRecord]]):
        self.data = FakeData(objects)
        self.link = FakeLinkTable(records)


def member_record(group: FakeObject, member: FakeObject) -> tuple[int, int, FakeRecord]:
    return (
        group.dnt,
        member.dnt,
        FakeRecord(link_DNT=group.dnt, backlink_DNT=member.dnt, link_base=1),
    )


def build_directory() -> tuple[FakeDatabase, dict[str, FakeObject]]:
    """Build a small directory with nested groups, a primary group, cycles and foreign references.

    Layout (a member link means "group contains member")::

        alice --member--> Nested A --member--> Nested B --member--> High Priv
        alice --member--> Mid Group --member--> High Priv
        alice --member--> Cycle A <--> Cycle B
        High Priv --member--> Broken (link to a missing DNT)
        High Priv --member--> Foreign Phantom Group (foreign domain, phantom)
        FSP (foreign SID) --member--> High Priv
    """
    objects = [
        FakeObject(1, "DC=LOCAL,DC=TEST", LOCAL_DOMAIN_SID, ["domainDNS", "domain", "top"], name="local"),
        FakeObject(
            2,
            "DC=FOREIGN,DC=TEST",
            FOREIGN_DOMAIN_SID,
            ["domainDNS", "domain", "top"],
            name="foreign",
            is_phantom=True,
        ),
        FakeObject(
            10,
            "CN=alice,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1100",
            ["user", "organizationalPerson", "person", "top"],
            name="alice",
            primary_group_id=513,
        ),
        FakeObject(
            11,
            "CN=bob,CN=Users,DC=LOCAL,DC=TEST",
            f"{OTHER_FOREIGN_DOMAIN_SID}-1100",
            ["user", "organizationalPerson", "person", "top"],
            name="bob",
            primary_group_id=513,
        ),
        FakeObject(
            20,
            "CN=Domain Users,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-513",
            ["group", "top"],
            name="Domain Users",
        ),
        FakeObject(
            21,
            "CN=Nested A,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1201",
            ["group", "top"],
            name="Nested A",
        ),
        FakeObject(
            22,
            "CN=Nested B,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1202",
            ["group", "top"],
            name="Nested B",
        ),
        FakeObject(
            23,
            "CN=High Priv,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1203",
            ["group", "top"],
            name="High Priv",
        ),
        FakeObject(
            24,
            "CN=Mid Group,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1204",
            ["group", "top"],
            name="Mid Group",
        ),
        FakeObject(
            25,
            "CN=Cycle A,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1301",
            ["group", "top"],
            name="Cycle A",
        ),
        FakeObject(
            26,
            "CN=Cycle B,CN=Users,DC=LOCAL,DC=TEST",
            f"{LOCAL_DOMAIN_SID}-1302",
            ["group", "top"],
            name="Cycle B",
        ),
        FakeObject(
            27,
            "CN=Foreign Phantom Group,DC=FOREIGN,DC=TEST",
            f"{FOREIGN_DOMAIN_SID}-1303",
            ["group", "top"],
            name="Foreign Phantom Group",
            is_phantom=True,
        ),
        FakeObject(
            30,
            "CN=S-1-5-21-555-666-777-2200,CN=ForeignSecurityPrincipals,DC=LOCAL,DC=TEST",
            f"{OTHER_FOREIGN_DOMAIN_SID}-2200",
            ["foreignSecurityPrincipal", "top"],
            name=f"{OTHER_FOREIGN_DOMAIN_SID}-2200",
        ),
    ]
    objects_by_name = {obj.name: obj for obj in objects}

    alice = objects_by_name["alice"]
    fsp = objects_by_name[f"{OTHER_FOREIGN_DOMAIN_SID}-2200"]
    nested_a = objects_by_name["Nested A"]
    nested_b = objects_by_name["Nested B"]
    high = objects_by_name["High Priv"]
    mid = objects_by_name["Mid Group"]
    cycle_a = objects_by_name["Cycle A"]
    cycle_b = objects_by_name["Cycle B"]
    foreign_group = objects_by_name["Foreign Phantom Group"]

    records = [
        member_record(nested_a, alice),
        # Duplicate physical records for the same logical membership
        member_record(nested_a, alice),
        member_record(nested_a, alice),
        member_record(nested_b, nested_a),
        member_record(high, nested_b),
        member_record(mid, alice),
        member_record(high, mid),
        member_record(cycle_a, alice),
        member_record(cycle_b, cycle_a),
        member_record(cycle_a, cycle_b),
        member_record(high, fsp),
        member_record(foreign_group, high),
        # A dangling link whose target object is absent from this database
        (9999, high.dnt, FakeRecord(link_DNT=9999, backlink_DNT=high.dnt, link_base=1)),
    ]

    return FakeDatabase(objects, records), objects_by_name


@pytest.fixture
def directory() -> tuple[FakeDatabase, dict[str, FakeObject]]:
    return build_directory()


@pytest.fixture
def tracer(directory: tuple[FakeDatabase, dict[str, FakeObject]]) -> MembershipTracer:
    db, _ = directory
    return MembershipTracer(db)


def path_descriptions(trace: MembershipTrace) -> list[str]:
    return [path.describe() for path in trace.paths]


def test_sid_domain() -> None:
    assert sid_domain(f"{LOCAL_DOMAIN_SID}-513") == LOCAL_DOMAIN_SID
    assert sid_domain("S-1-5-32-544") == "S-1-5-32"
    assert sid_domain("not-a-sid") is None
    assert sid_domain(None) is None


def test_nested_groups_and_primary_group(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    # Alice's primary group is resolved from her full SID, not just the RID
    assert trace.paths_to(objects["Domain Users"])[0].kinds == (EdgeKind.PRIMARY_GROUP,)

    # The nested group chain is confirmed and retains every intermediate group
    nested_paths = trace.paths_to(objects["High Priv"])
    assert len(nested_paths) == 2  # Nested A -> Nested B -> High Priv and Mid Group -> High Priv
    assert {len(path.edges) for path in nested_paths} == {2, 3}
    for path in nested_paths:
        assert [edge.kind for edge in path.edges] == [EdgeKind.EXPLICIT_MEMBER] * len(path.edges)
        assert path.status == PathStatus.CONFIRMED
        assert path.complete
        assert path.target == objects["High Priv"]
        assert path.edges[0].source == objects["alice"]

    # Every confirmed path can explain its evidence record
    for path in trace.confirmed_paths:
        for edge in path.edges:
            if edge.kind == EdgeKind.EXPLICIT_MEMBER:
                assert edge.evidence["attribute"] == "member"
                assert edge.evidence["link_table"]["link_DNT"] == edge.target_dnt
                assert edge.evidence["link_table"]["backlink_DNT"] == edge.source_dnt
            else:
                assert edge.kind == EdgeKind.PRIMARY_GROUP
                assert edge.evidence["attribute"] == "primaryGroupID"
                assert edge.evidence["derived_objectSid"] == edge.target_sid

    assert trace.complete is False  # because of the deliberately broken and foreign edges
    assert trace.confirmed_paths


def test_primary_group_is_not_matched_by_rid_across_domains(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    primary_paths = [path for path in trace.paths if path.edges and path.edges[0].kind == EdgeKind.PRIMARY_GROUP]
    assert primary_paths
    assert all(path.target == objects["Domain Users"] for path in primary_paths)
    assert all(path.target.sid == f"{LOCAL_DOMAIN_SID}-513" for path in primary_paths)
    assert all(
        path.target != objects["Foreign Phantom Group"]
        for path in trace.paths
        if all(edge.kind == EdgeKind.PRIMARY_GROUP for edge in path.edges)
    )

    # Bob's SID belongs to another domain. The same RID 513 must not resolve to the local Domain Users group.
    bob_trace = tracer.trace(objects["bob"])
    assert bob_trace.paths_to(objects["Domain Users"]) == []
    assert len(bob_trace.paths) == 1
    bob_path = bob_trace.paths[0]
    assert bob_path.status == PathStatus.FOREIGN
    assert bob_path.edges[0].kind == EdgeKind.PRIMARY_GROUP
    assert bob_path.target is None
    assert UnresolvedReason.FOREIGN_DOMAIN in bob_path.reasons
    assert bob_path.edges[0].evidence["derived_objectSid"] == f"{OTHER_FOREIGN_DOMAIN_SID}-513"
    assert bob_path.edges[0].evidence["sid_scope"] == "foreign_domain"
    assert bob_trace.complete is False


def test_group_cycle_keeps_cycle_edge(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    cycle_paths = trace.cycle_paths
    assert cycle_paths
    cycle_path = cycle_paths[0]
    assert cycle_path.status == PathStatus.CYCLE
    assert cycle_path.reasons == (UnresolvedReason.CYCLE,)
    assert cycle_path.edges[-1].target == objects["Cycle A"]
    assert cycle_path.edges[-1].reasons == (UnresolvedReason.CYCLE,)
    assert cycle_path.complete is False

    unresolved = [edge for edge in trace.unresolved_edges if UnresolvedReason.CYCLE in edge.reasons]
    assert len(unresolved) == 1
    assert unresolved[0].evidence["link_table"]["link_DNT"] == objects["Cycle A"].dnt


def test_duplicate_paths_and_duplicate_links(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    # Two distinct routes to High Priv are both retained, not collapsed into one path
    high_paths = trace.paths_to(objects["High Priv"])
    assert len(high_paths) == 2
    assert {tuple(edge.source_dn for edge in path.edges) for path in high_paths} == {
        (
            "CN=alice,CN=Users,DC=LOCAL,DC=TEST",
            "CN=Nested A,CN=Users,DC=LOCAL,DC=TEST",
            "CN=Nested B,CN=Users,DC=LOCAL,DC=TEST",
        ),
        ("CN=alice,CN=Users,DC=LOCAL,DC=TEST", "CN=Mid Group,CN=Users,DC=LOCAL,DC=TEST"),
    }

    # The three physical records for the same membership are one logical edge plus duplicate evidence
    nested_a_paths = trace.paths_to(objects["Nested A"])
    assert len(nested_a_paths) == 1
    assert nested_a_paths[0].edges[0].occurrences == 3
    assert len(trace.duplicate_links) == 2
    assert all(duplicate["link_DNT"] == objects["Nested A"].dnt for duplicate in trace.duplicate_links)


def test_foreign_principal_and_missing_target_are_unresolved(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    # Phantom cross-domain group is named but not expanded
    phantom_edges = [edge for edge in trace.unresolved_edges if UnresolvedReason.PHANTOM in edge.reasons]
    assert len(phantom_edges) == 1
    assert phantom_edges[0].target == objects["Foreign Phantom Group"]
    foreign_paths = trace.foreign_paths
    assert any(path.target == objects["Foreign Phantom Group"] for path in foreign_paths)

    # A link whose target object is missing is retained with its raw DNT
    missing_edges = [edge for edge in trace.unresolved_edges if UnresolvedReason.MISSING_TARGET in edge.reasons]
    assert len(missing_edges) == 1
    assert missing_edges[0].target is None
    assert missing_edges[0].target_dnt == 9999
    assert missing_edges[0].evidence["link_table"]["backlink_DNT"] == objects["High Priv"].dnt

    # None of this completes the cross-domain expansion
    assert trace.complete is False
    assert any("not a live access check" in limitation for limitation in trace.limitations)

    # A foreign security principal as the subject is a boundary, not a silently empty result.
    # Its local group memberships are still provable; its home-domain identity is not.
    fsp = objects[f"{OTHER_FOREIGN_DOMAIN_SID}-2200"]
    fsp_trace = tracer.trace(fsp)
    assert fsp_trace.complete is False
    assert fsp_trace.paths_to(objects["High Priv"])
    assert fsp_trace.paths_to(objects["High Priv"])[0].kinds == (EdgeKind.EXPLICIT_MEMBER,)
    assert fsp_trace.foreign_paths
    assert any(edge.reasons == (UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL,) for edge in fsp_trace.unresolved_edges)
    assert any("home-domain" in limitation for limitation in fsp_trace.limitations)


def test_trace_explanation_and_serialisation(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])
    explanation = trace.explain()

    assert "Offline membership trace" in explanation
    assert "Confirmed paths:" in explanation
    assert "Unresolved edges:" in explanation
    assert "Limitations:" in explanation
    assert "not a live access check" in explanation
    assert objects["High Priv"].sid in explanation

    data = trace.as_dict()
    assert data["subject"]["sid"] == objects["alice"].sid
    assert data["offline_evidence_only"] is True
    assert data["complete"] is False
    assert data["confirmed_paths"]
    assert data["unresolved_edges"]
    assert all("kind" in edge for path in data["paths"] for edge in path["edges"])


def test_max_depth_and_missing_edge_limit(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory

    shallow = tracer.trace(objects["alice"], max_depth=2)
    assert shallow.truncated is False
    assert any(UnresolvedReason.DEPTH_LIMIT in path.reasons for path in shallow.paths)
    assert any(UnresolvedReason.DEPTH_LIMIT in edge.reasons for edge in shallow.unresolved_edges)

    limited = tracer.trace(objects["alice"], max_paths=2)
    assert limited.truncated is True
    assert len(limited.paths) <= 2
    assert any(UnresolvedReason.PATH_LIMIT in edge.reasons for edge in limited.unresolved_edges)


def test_invalid_primary_group_id_is_retained(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    objects["alice"].primary_group_id = "not-a-rid"

    trace = tracer.trace(objects["alice"])
    primary_paths = [path for path in trace.paths if path.edges[0].kind == EdgeKind.PRIMARY_GROUP]

    assert len(primary_paths) == 1
    assert primary_paths[0].status == PathStatus.PARTIAL
    assert primary_paths[0].reasons == (UnresolvedReason.INVALID_PRIMARY_GROUP_ID,)
    assert primary_paths[0].edges[0].evidence["primaryGroupID"] == "not-a-rid"
    assert trace.paths_to(objects["Domain Users"]) == []


def test_no_primary_group_edges_when_disabled(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"], include_primary_group=False)

    assert all(edge.kind == EdgeKind.EXPLICIT_MEMBER for path in trace.paths for edge in path.edges)
    assert trace.paths_to(objects["Domain Users"]) == []


def test_unknown_subject_is_rejected(tracer: MembershipTracer) -> None:
    with pytest.raises(ValueError, match="No object found"):
        tracer.trace("CN=does-not-exist,DC=LOCAL,DC=TEST")


def test_subject_can_be_selected_by_dnt_sid_or_dn(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    alice = objects["alice"]

    assert len(tracer.trace(alice.dnt).paths) == len(tracer.trace(alice).paths)
    assert len(tracer.trace(alice.sid).paths) == len(tracer.trace(alice).paths)
    assert len(tracer.trace(alice.dn).paths) == len(tracer.trace(alice).paths)


def test_offline_disclaimer_is_always_present(
    directory: tuple[FakeDatabase, dict[str, FakeObject]], tracer: MembershipTracer
) -> None:
    _, objects = directory
    trace = tracer.trace(objects["alice"])

    assert any("not a live access check" in limitation for limitation in trace.limitations)
    assert trace.as_dict()["offline_evidence_only"] is True
