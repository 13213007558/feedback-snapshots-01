from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.ntds import NTDS

import pytest

from dissect.database.ese.ntds.membership import (
    MembershipRelation,
    MembershipTracer,
    trace_group_members,
    trace_memberships,
)
from dissect.database.ese.ntds.util import sid_domain, sid_for_rid, sid_rid

DOMAIN = "S-1-5-21-100-200-300"
FOREIGN_DOMAIN = "S-1-5-21-900-800-700"


@dataclass
class FixtureObject:
    """A minimal NTDS-like object used to exercise the offline membership tracer."""

    dnt_value: int
    name_value: str
    sid_value: str | None
    classes: list[str]
    primary_group_id_value: int | None = None
    phantom: bool = False
    explicit_members: list[int] = field(default_factory=list)
    dn_value: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def dnt(self) -> int:
        return self.dnt_value

    @property
    def name(self) -> str:
        return self.name_value

    @property
    def sid(self) -> str | None:
        return self.sid_value

    @property
    def primary_group_id(self) -> int | None:
        return self.primary_group_id_value

    @property
    def object_class(self) -> list[str]:
        return self.classes

    @property
    def is_phantom(self) -> bool:
        return self.phantom

    @property
    def distinguished_name(self) -> str:
        return self.dn_value or f"CN={self.name}"

    def get(self, name: str) -> Any:
        if name == "member":
            return list(self.explicit_members)
        if name == "primaryGroupID":
            return self.primary_group_id
        if name == "objectSid":
            return self.sid_value
        if name == "objectClass":
            return self.classes
        return self.attributes.get(name)

    def __getattr__(self, name: str) -> Any:
        try:
            return self.attributes[name]
        except KeyError:
            raise AttributeError(name) from None


class FixtureDataTable:
    def __init__(self, graph: FixtureGraph):
        self.graph = graph

    def iter(self) -> Iterator[FixtureObject]:
        return iter(self.graph.objects)

    def get(self, dnt: int) -> FixtureObject:
        if (obj := self.graph.by_dnt.get(dnt)) is None:
            raise KeyError(dnt)
        return obj

    def search(self, **kwargs: Any) -> Iterator[FixtureObject]:
        for obj in self.graph.objects:
            if all(obj.get(name) == value for name, value in kwargs.items()):
                yield obj


class FixtureLinkTable:
    def __init__(self, graph: FixtureGraph):
        self.graph = graph

    def raw_backlinks(self, dnt: int, name: str | None = None) -> Iterator[tuple[int, int]]:
        assert name == "member"
        for source_dnt, targets in self.graph.member_links.items():
            for target_dnt in targets:
                if target_dnt == dnt:
                    yield 2, source_dnt

    def raw_links(self, dnt: int, name: str | None = None) -> Iterator[tuple[int, int]]:
        assert name == "member"
        for target_dnt in self.graph.member_links.get(dnt, []):
            yield 2, target_dnt

    def resolve(self, dnt: int) -> FixtureObject | None:
        return self.graph.by_dnt.get(dnt)

    def backlinks(self, dnt: int, name: str | None = None) -> Iterator[FixtureObject]:
        for _, source_dnt in self.raw_backlinks(dnt, name):
            if (obj := self.resolve(source_dnt)) is not None:
                yield obj

    def links(self, dnt: int, name: str | None = None) -> Iterator[FixtureObject]:
        for _, target_dnt in self.raw_links(dnt, name):
            if (obj := self.resolve(target_dnt)) is not None:
                yield obj


class FixtureGraph:
    def __init__(self, objects: list[FixtureObject]):
        self.objects = objects
        self.by_dnt = {obj.dnt: obj for obj in objects if obj.dnt is not None}
        self.member_links: dict[int, list[int]] = {
            obj.dnt: list(obj.explicit_members) for obj in objects if obj.explicit_members
        }
        self.data = FixtureDataTable(self)
        self.link = FixtureLinkTable(self)


def fixture_tracer(objects: list[FixtureObject]) -> MembershipTracer:
    return MembershipTracer(objects=objects)


def test_sid_helpers_keep_domain_scope() -> None:
    assert sid_domain(f"{DOMAIN}-513") == DOMAIN
    assert sid_rid(f"{DOMAIN}-513") == 513
    assert sid_for_rid(DOMAIN, 513) == f"{DOMAIN}-513"
    assert sid_domain("not-a-sid") is None
    assert sid_for_rid(DOMAIN, None) is None


def test_explicit_and_primary_paths_are_labelled_separately() -> None:
    users = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"])
    nested = FixtureObject(2, "nested", f"{DOMAIN}-1100", ["group"], explicit_members=[10])
    admins = FixtureObject(3, "admins", f"{DOMAIN}-512", ["group"], explicit_members=[2])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)

    trace = fixture_tracer([users, nested, admins, account]).trace(account)

    assert trace.complete
    by_group = {path.group.name: path for path in trace.confirmed_paths}
    assert set(by_group) == {"users", "nested", "admins"}

    assert by_group["users"].relations == (MembershipRelation.PRIMARY_GROUP,)
    assert by_group["users"].kind == "primaryGroupID"
    assert by_group["nested"].relations == (MembershipRelation.MEMBER,)
    assert by_group["admins"].relations == (MembershipRelation.MEMBER, MembershipRelation.MEMBER)
    assert by_group["admins"].sources == ("member", "member")
    assert by_group["admins"].observed_sources == ("memberOf", "memberOf")


def test_primary_group_does_not_match_rid_in_another_domain() -> None:
    local_users = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"])
    foreign_users = FixtureObject(2, "foreign users", f"{FOREIGN_DOMAIN}-513", ["group"], phantom=True)
    local_account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)
    foreign_account = FixtureObject(11, "bob", f"{FOREIGN_DOMAIN}-1002", ["user"], primary_group_id_value=513)

    trace = fixture_tracer([local_users, foreign_users, local_account, foreign_account]).trace(local_account)

    assert [path.group.name for path in trace.confirmed_paths] == ["users"]
    assert all(path.group_sid == f"{DOMAIN}-513" for path in trace.paths)


def test_primary_group_target_missing_keeps_unresolved_edge() -> None:
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)

    trace = fixture_tracer([account]).trace(account)

    assert not trace.complete
    assert len(trace.paths) == 1
    assert trace.paths[0].relations == (MembershipRelation.PRIMARY_GROUP,)
    assert trace.paths[0].group is None
    assert trace.paths[0].group_sid == f"{DOMAIN}-513"
    assert not trace.paths[0].resolved
    assert any("primaryGroupID" in (edge.reason or "") for edge in trace.unresolved_edges)


def test_foreign_security_principal_in_downward_trace_is_a_boundary() -> None:
    fsp = FixtureObject(
        20,
        "fsp",
        f"{FOREIGN_DOMAIN}-1105",
        ["foreignSecurityPrincipal"],
        dn_value=f"CN={FOREIGN_DOMAIN}-1105,CN=FOREIGNSECURITYPRINCIPALS,DC=SEVENKINGDOMS,DC=LOCAL",
    )
    team = FixtureObject(21, "team", f"{DOMAIN}-1200", ["group"], explicit_members=[20])

    trace = fixture_tracer([fsp, team]).trace_members(team)

    assert not trace.complete
    assert [obj.name for obj in trace.foreign_principals] == ["fsp"]
    assert any(edge.relation == MembershipRelation.MEMBER and not edge.expandable for edge in trace.unresolved_edges)
    fsp_path = next(path for path in trace.paths if path.member is not None and path.member.name == "fsp")
    assert fsp_path.locally_proven
    assert not fsp_path.expandable
    assert not fsp_path.resolved


def test_foreign_security_principal_as_member_boundary_does_not_get_expanded() -> None:
    fsp = FixtureObject(
        20,
        "fsp",
        f"{FOREIGN_DOMAIN}-1105",
        ["foreignSecurityPrincipal"],
        dn_value=f"CN={FOREIGN_DOMAIN}-1105,CN=FOREIGNSECURITYPRINCIPALS,DC=SEVENKINGDOMS,DC=LOCAL",
    )
    team = FixtureObject(21, "team", f"{DOMAIN}-1200", ["group"], explicit_members=[20])
    # A local group can also be a member of another local group; this relation is still provable.
    super_team = FixtureObject(22, "super team", f"{DOMAIN}-1201", ["group"], explicit_members=[21])

    trace = fixture_tracer([fsp, team, super_team]).trace(fsp)

    assert {path.group.name for path in trace.paths if path.group is not None} == {"team", "super team"}
    top = next(path for path in trace.paths if path.group is not None and path.group.name == "super team")
    assert top.locally_proven
    assert top.expandable
    assert top.resolved


def test_missing_explicit_target_keeps_unresolved_edge() -> None:
    ghost = FixtureObject(99, "ghost", f"{DOMAIN}-1300", ["group"], explicit_members=[10])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    graph = FixtureGraph([ghost, account])
    # Simulate a dangling link: the group exists, but the member target DNT does not.
    graph.member_links[99] = [77]

    trace = MembershipTracer(graph).trace_members(ghost)

    assert not trace.complete
    assert len(trace.unresolved_edges) == 1
    edge = trace.unresolved_edges[0]
    assert edge.member_dnt == 77
    assert edge.member is None
    assert "not found" in (edge.reason or "")


def test_missing_group_target_in_upward_trace_is_preserved() -> None:
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    graph = FixtureGraph([account])
    # A backlink points at a group DNT that does not exist.
    graph.member_links[77] = [10]

    trace = MembershipTracer(graph).trace(account)

    assert not trace.complete
    assert len(trace.paths) == 1
    assert trace.paths[0].group is None
    assert trace.paths[0].relations == (MembershipRelation.MEMBER,)
    assert not trace.paths[0].locally_proven


def test_group_cycle_is_reported_and_does_not_loop_forever() -> None:
    a = FixtureObject(1, "a", f"{DOMAIN}-1401", ["group"], explicit_members=[10])
    b = FixtureObject(2, "b", f"{DOMAIN}-1402", ["group"], explicit_members=[1])
    a.explicit_members.append(2)
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    trace = fixture_tracer([a, b, account]).trace(account)

    assert trace.cycles
    assert not trace.complete
    assert any(edge.reason and "cycle" in edge.reason for edge in trace.unresolved_edges)
    assert {path.group.name for path in trace.paths if path.group is not None} == {"a", "b"}


def test_duplicate_paths_are_recorded_separately() -> None:
    top = FixtureObject(1, "top", f"{DOMAIN}-1500", ["group"])
    left = FixtureObject(2, "left", f"{DOMAIN}-1501", ["group"], explicit_members=[10])
    right = FixtureObject(3, "right", f"{DOMAIN}-1502", ["group"], explicit_members=[10])
    top.explicit_members = [2, 3]
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    trace = fixture_tracer([top, left, right, account]).trace(account)
    tops = [path for path in trace.paths if path.group is not None and path.group.name == "top"]

    assert len(tops) == 2
    assert all(path.resolved for path in tops)
    assert trace.duplicates == []


def test_duplicate_edges_are_deduplicated_and_reported() -> None:
    group = FixtureObject(1, "group", f"{DOMAIN}-1600", ["group"], explicit_members=[10, 10])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    trace = fixture_tracer([group, account]).trace(account)

    assert len(trace.paths) == 1
    assert len(trace.duplicates) == 1
    assert trace.confirmed_paths


def test_downward_trace_includes_nested_groups_and_primary_members() -> None:
    top = FixtureObject(1, "top", f"{DOMAIN}-1700", ["group"], explicit_members=[2, 10])
    nested = FixtureObject(2, "nested", f"{DOMAIN}-1701", ["group"], explicit_members=[11])
    primary_only = FixtureObject(12, "carol", f"{DOMAIN}-1012", ["user"], primary_group_id_value=1700)
    alice = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    bob = FixtureObject(11, "bob", f"{DOMAIN}-1002", ["user"])

    trace = fixture_tracer([top, nested, primary_only, alice, bob]).trace_members(top)

    assert trace.complete
    assert {path.member.name for path in trace.paths} == {"nested", "alice", "bob", "carol"}
    carol_path = next(path for path in trace.paths if path.member.name == "carol")
    assert carol_path.relations == (MembershipRelation.PRIMARY_GROUP,)


def test_downward_primary_group_respects_domain_scope() -> None:
    top = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"])
    local = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)
    foreign = FixtureObject(11, "bob", f"{FOREIGN_DOMAIN}-1002", ["user"], primary_group_id_value=513)

    trace = fixture_tracer([top, local, foreign]).trace_members(top)

    assert {path.member.name for path in trace.paths} == {"alice"}


def test_json_explanation_distinguishes_confirmed_and_unknown() -> None:
    users = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"])
    phantom = FixtureObject(2, "north users", f"{FOREIGN_DOMAIN}-513", ["group"], phantom=True)
    fsp = FixtureObject(
        3,
        "fsp",
        f"{FOREIGN_DOMAIN}-1105",
        ["foreignSecurityPrincipal"],
        dn_value=f"CN={FOREIGN_DOMAIN}-1105,CN=FOREIGNSECURITYPRINCIPALS,DC=SEVENKINGDOMS,DC=LOCAL",
    )
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)

    graph = FixtureGraph([users, phantom, fsp, account])
    # "users" is a member of a cross-domain phantom group, a group whose target is missing, and a group
    # that also contains a foreign security principal.
    graph.member_links[2] = [1]
    graph.member_links[3] = [1]
    graph.member_links[77] = [1]

    trace = MembershipTracer(graph).trace(account)
    payload = trace.to_dict()

    assert payload["offline"] is True
    assert "does not prove" in payload["warning"]
    assert payload["complete"] is False
    assert any(step["relation"] == "primaryGroupID" for step in payload["confirmed_paths"][0]["steps"])
    assert payload["unresolved_edges"]
    assert payload["incomplete_paths"]
    # The FSP placeholder is preserved as a boundary, but its external identity is not expanded.
    assert [obj["name"] for obj in payload["foreign_principals"]] == ["fsp"]


def test_trace_requires_a_source() -> None:
    with pytest.raises(TypeError):
        MembershipTracer()


def test_trace_rejects_unknown_direction() -> None:
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    with pytest.raises(ValueError, match="Unsupported membership direction"):
        fixture_tracer([account]).trace(account, direction="sideways")


def test_max_depth_is_reported() -> None:
    a = FixtureObject(1, "a", f"{DOMAIN}-1900", ["group"], explicit_members=[10])
    b = FixtureObject(2, "b", f"{DOMAIN}-1901", ["group"], explicit_members=[1])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    trace = fixture_tracer([a, b, account]).trace(account, max_depth=1)

    assert trace.max_depth_reached
    assert not trace.complete


def test_convenience_functions() -> None:
    group = FixtureObject(1, "group", f"{DOMAIN}-2000", ["group"], explicit_members=[10])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    graph = FixtureGraph([group, account])

    assert trace_memberships(graph, account).paths
    assert trace_group_members(graph, group).paths


def test_real_fixture_traces_explicit_and_primary_paths(goad: NTDS) -> None:
    account = next(goad.search(sAMAccountName="cersei.lannister"))

    trace = goad.trace_memberships(account)

    assert trace.complete
    assert trace.confirmed_paths
    assert {path.group_sid for path in trace.confirmed_paths} >= {
        "S-1-5-21-227512471-3105770690-3802255443-513",  # Domain Users, via primaryGroupID
        "S-1-5-21-227512471-3105770690-3802255443-512",  # Domain Admins, via member
    }

    domain_users = next(path for path in trace.paths if path.group_sid.endswith("-513"))
    assert domain_users.relations == (MembershipRelation.PRIMARY_GROUP,)
    assert domain_users.observed_sources == ("primaryGroupID",)

    domain_admins = next(path for path in trace.paths if path.group_sid.endswith("-512"))
    assert MembershipRelation.MEMBER in domain_admins.relations
    assert domain_admins.observed_sources[0] == "memberOf"


def test_real_fixture_does_not_match_foreign_primary_group_by_rid(goad: NTDS) -> None:
    # "Guest" exists in both the local domain and as a phantom object from the NORTH domain.
    # Both have primaryGroupID 514, but only the local account belongs to the local Domain Guests group.
    local_guest = next(
        u for u in goad.users() if u.sam_account_name == "Guest" and u.sid.startswith("S-1-5-21-227512471")
    )

    trace = goad.trace_memberships(local_guest)
    primary_paths = [path for path in trace.paths if path.relations == (MembershipRelation.PRIMARY_GROUP,)]

    assert len(primary_paths) == 1
    assert primary_paths[0].member_sid == "S-1-5-21-227512471-3105770690-3802255443-501"
    assert primary_paths[0].group_sid == "S-1-5-21-227512471-3105770690-3802255443-514"
    # The phantom NORTH-domain Guest also has RID 514, but must not be linked through primaryGroupID.
    assert all(path.group_sid != "S-1-5-21-459184689-3312531310-188885708-514" for path in trace.paths)


def test_real_fixture_foreign_security_principal_remains_unresolved(goad: NTDS) -> None:
    fsp = next(
        obj
        for obj in goad.search(objectClass="foreignSecurityPrincipal")
        if obj.sid.startswith("S-1-5-21-1398578290-1256418943-189470967")
    )

    trace = goad.trace_memberships(fsp)

    assert trace.foreign_principals
    assert not trace.complete
    assert any(edge.relation == MembershipRelation.FOREIGN_SECURITY_PRINCIPAL for edge in trace.unresolved_edges)
    assert not any(cycle for cycle in trace.cycles)


def test_real_fixture_group_members_are_labelled(goad: NTDS) -> None:
    group = next(goad.search(sAMAccountName="Domain Admins"))

    trace = goad.trace_group_members(group)

    assert trace.complete
    assert {path.member.sam_account_name for path in trace.paths} == {"Administrator", "cersei.lannister"}
    assert all(path.relations == (MembershipRelation.MEMBER,) for path in trace.paths)


def test_missing_sid_scope_is_reported_as_gap() -> None:
    # An object without a SID cannot have its primaryGroupID scoped, so the trace must not claim completeness.
    account = FixtureObject(10, "alice", None, ["user"], primary_group_id_value=513)
    group = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"], explicit_members=[10])

    trace = fixture_tracer([group, account]).trace(account)

    assert trace.gaps
    assert not trace.complete
    assert any("primaryGroupID" in gap for gap in trace.gaps)
    # The explicit member edge is still provable even though the primary group cannot be scoped.
    assert all(path.group.name == "users" for path in trace.confirmed_paths)


def test_phantom_start_is_a_gap_not_a_foreign_principal() -> None:
    phantom = FixtureObject(2, "north user", f"{FOREIGN_DOMAIN}-1002", ["user"], phantom=True)

    trace = fixture_tracer([phantom]).trace(phantom)

    assert trace.gaps
    assert not trace.foreign_principals
    assert not trace.complete


def test_explain_reports_confirmed_and_unknown_parts() -> None:
    group = FixtureObject(1, "users", f"{DOMAIN}-513", ["group"], explicit_members=[10])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    graph = FixtureGraph([group, account])
    graph.member_links[77] = [10]

    explanation = MembershipTracer(graph).trace(account).explain()

    assert any(line.startswith("confirmed:") for line in explanation)
    assert any(line.startswith("incomplete:") for line in explanation)
    assert any(line.startswith("note:") for line in explanation)


def test_primary_group_helper_exposes_expected_sid() -> None:
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"], primary_group_id_value=513)
    tracer = fixture_tracer([account])

    expected_sid, group = tracer.primary_group(account)

    assert expected_sid == f"{DOMAIN}-513"
    assert group is None


def test_compatibility_aliases() -> None:
    group = FixtureObject(1, "group", f"{DOMAIN}-2001", ["group"], explicit_members=[10])
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])
    tracer = fixture_tracer([group, account])

    trace = tracer.resolve(account)
    assert trace.by_group()["group"][0].steps
    assert trace.by_group_sid()[f"{DOMAIN}-2001"][0].objects
    assert trace.by_group_sid()[f"{DOMAIN}-2001"][0].sids == (f"{DOMAIN}-1001", f"{DOMAIN}-2001")
    assert trace.unresolved == trace.unresolved_edges
    assert tracer.membership_paths(account) == trace.paths


def test_ntds_membership_paths_helper(goad: NTDS) -> None:
    account = next(goad.search(sAMAccountName="cersei.lannister"))

    paths = goad.membership_paths(account)

    assert paths
    assert all(path.observed_sources for path in paths)
    assert goad.resolve_membership(account).paths == paths


def test_cycle_edge_is_locally_proven_but_not_expandable() -> None:
    a = FixtureObject(1, "a", f"{DOMAIN}-2101", ["group"], explicit_members=[10])
    b = FixtureObject(2, "b", f"{DOMAIN}-2102", ["group"], explicit_members=[1])
    a.explicit_members.append(2)
    account = FixtureObject(10, "alice", f"{DOMAIN}-1001", ["user"])

    trace = fixture_tracer([a, b, account]).trace(account)

    cycle_paths = [path for path in trace.paths if any(edge.reason and "cycle" in edge.reason for edge in path.edges)]
    assert cycle_paths
    assert all(path.locally_proven for path in cycle_paths)
    assert all(not path.expandable for path in cycle_paths)
