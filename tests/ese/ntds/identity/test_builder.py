from __future__ import annotations

import pytest

from dissect.database.ese.ntds.identity import (
    DisplayPathBuilder,
    InMemoryObjectSource,
    ObjectState,
    PathBuildError,
    PathIssueKind,
    Snapshot,
    identity_from_mapping,
)


def _snapshot(records: list[dict], *, strict: bool = False) -> Snapshot:
    return Snapshot.from_mappings(records, label="fixture", strict_paths=strict)


ROOT = {"dnt": 2, "pdnt": 0, "name": "$ROOT_OBJECT$"}


def test_builds_full_path_target_first() -> None:
    snapshot = _snapshot(
        [
            ROOT,
            {"dnt": 10, "pdnt": 2, "guid": "10000000-0000-0000-0000-000000000001", "name": "local", "rdn_type": "dc"},
            {"dnt": 11, "pdnt": 10, "guid": "10000000-0000-0000-0000-000000000002", "name": "dom", "rdn_type": "dc"},
            {"dnt": 12, "pdnt": 11, "guid": "10000000-0000-0000-0000-000000000003", "name": "Users", "rdn_type": "cn"},
        ]
    )
    path = snapshot.path(12)

    assert path.distinguished_name == "cn=Users,dc=dom,dc=local"
    assert path.is_complete
    assert path.dnts == [12, 11, 10, 2]
    assert path.retraces()
    # The root segment is retained for traceability even though it has no rendered RDN.
    assert path.segments[-1].identity.dnt == 2
    assert any(issue.kind == PathIssueKind.ROOT_REACHED for issue in path.issues)


def test_missing_parent_is_diagnosed_not_fabricated() -> None:
    snapshot = _snapshot(
        [
            {"dnt": 20, "pdnt": 99, "guid": "20000000-0000-0000-0000-000000000001", "name": "orphan", "rdn_type": "cn"},
        ]
    )
    path = snapshot.path(20)

    assert not path.is_complete
    assert path.distinguished_name == "cn=orphan"
    assert [issue.kind for issue in path.issues] == [PathIssueKind.MISSING_PARENT]
    assert path.issues[0].dnt == 99
    assert path.retraces()


def test_missing_rdn_on_non_root_is_diagnosed() -> None:
    snapshot = _snapshot(
        [
            ROOT,
            {"dnt": 30, "pdnt": 2, "guid": "30000000-0000-0000-0000-000000000001", "name": "no-rdn-type"},
        ]
    )
    path = snapshot.path(30)

    assert not path.is_complete
    assert any(issue.kind == PathIssueKind.MISSING_RDN for issue in path.issues)


def test_cycle_is_diagnosed_without_recursion_error() -> None:
    records = [
        {"dnt": 10, "pdnt": 12, "guid": "40000000-0000-0000-0000-000000000001", "name": "a", "rdn_type": "cn"},
        {"dnt": 11, "pdnt": 10, "guid": "40000000-0000-0000-0000-000000000002", "name": "b", "rdn_type": "cn"},
        {"dnt": 12, "pdnt": 11, "guid": "40000000-0000-0000-0000-000000000003", "name": "c", "rdn_type": "cn"},
    ]
    snapshot = _snapshot(records)
    path = snapshot.path(11)

    assert path.has_cycle
    assert not path.is_complete
    assert next(issue for issue in path.issues if issue.kind == PathIssueKind.CYCLE).detail
    # Every segment reached before the loop is still presented.
    assert path.dnts == [11, 10, 12]


def test_strict_builder_raises_on_cycle() -> None:
    records = [
        {"dnt": 10, "pdnt": 11, "guid": "50000000-0000-0000-0000-000000000001", "name": "a", "rdn_type": "cn"},
        {"dnt": 11, "pdnt": 10, "guid": "50000000-0000-0000-0000-000000000002", "name": "b", "rdn_type": "cn"},
    ]
    snapshot = _snapshot(records, strict=True)
    with pytest.raises(PathBuildError) as exc:
        snapshot.path(10)
    assert exc.value.dnt == 10
    assert any(issue.kind == PathIssueKind.CYCLE for issue in exc.value.issues)


def test_strict_builder_raises_on_missing_parent() -> None:
    snapshot = _snapshot(
        [{"dnt": 40, "pdnt": 98, "guid": "60000000-0000-0000-0000-000000000001", "name": "x", "rdn_type": "cn"}],
        strict=True,
    )
    with pytest.raises(PathBuildError):
        snapshot.path(40)


def test_multi_valued_rdn_is_flagged_and_rendered() -> None:
    snapshot = _snapshot(
        [
            {
                "dnt": 50,
                "pdnt": 0,
                "guid": "70000000-0000-0000-0000-000000000001",
                "name": "primary",
                "rdn_values": ["secondary"],
                "rdn_type": "cn",
            },
        ]
    )
    path = snapshot.path(50)

    assert path.distinguished_name == "cn=primary+cn=secondary"
    assert any(issue.kind == PathIssueKind.MULTI_VALUED_RDN for issue in path.issues)
    assert path.is_complete


def test_deleted_and_phantom_records_keep_their_state() -> None:
    snapshot = _snapshot(
        [
            ROOT,
            {
                "dnt": 60,
                "pdnt": 2,
                "guid": "80000000-0000-0000-0000-000000000001",
                "name": "tomb",
                "rdn_type": "cn",
                "is_deleted": True,
            },
            {
                "dnt": 61,
                "pdnt": 2,
                "guid": "80000000-0000-0000-0000-000000000002",
                "name": "ghost",
                "rdn_type": "cn",
                "is_phantom": True,
            },
        ]
    )

    deleted = snapshot.get(60)
    phantom = snapshot.get(61)
    assert deleted.state == ObjectState.DELETED
    assert not deleted.is_live
    assert phantom.state == ObjectState.PHANTOM
    assert not phantom.is_live
    # Paths are still constructed, but the records are never silently upgraded to live.
    assert snapshot.path(60).distinguished_name == "cn=tomb"
    assert snapshot.path(61).distinguished_name == "cn=ghost"


def test_builder_uses_injected_source_and_caches() -> None:
    source = InMemoryObjectSource(
        [
            identity_from_mapping(
                {"dnt": 1, "pdnt": 0, "guid": "90000000-0000-0000-0000-000000000001", "name": "root", "rdn_type": "dc"}
            )
        ]
    )
    builder = DisplayPathBuilder(source)
    first = builder.build(1)
    second = builder.build(1)
    assert first is second
