from __future__ import annotations

import json
from pathlib import Path

from tox.tox_env.python.approvals import (
    ApprovalGate,
    ArtifactRef,
    artifacts_from_python_deps,
)
from tox.tox_env.python.pip.req_file import PythonConstraints, PythonDeps


def test_policy_distinguishes_same_name_version_by_digest_and_source(tmp_path: Path) -> None:
    digest_a = "a" * 64
    digest_b = "b" * 64
    policy = tmp_path / "approvals.json"
    policy.write_text(
        json.dumps(
            {
                "approvals": [
                    {"id": "a", "name": "demo", "version": "1.0", "sha256": digest_a, "status": "approved"},
                    {"id": "b", "name": "demo", "version": "1.0", "sha256": digest_b, "status": "revoked"},
                ],
            },
        ),
    )
    gate = ApprovalGate(policy, tmp_path)
    artifacts = [
        ArtifactRef("demo", "1.0", str(tmp_path / "a.whl"), digest_a),
        ArtifactRef("demo", "1.0", str(tmp_path / "b.whl"), digest_b),
    ]

    evidence = gate.review(artifacts, "unit", raise_on_deny=False)

    assert [decision.status for decision in evidence.decisions] == ["approved", "revoked"]
    assert evidence.approved is False


def test_inactive_marker_requirement_is_not_evidence(tmp_path: Path) -> None:
    deps = PythonDeps('demo==1.0; python_version == "2.7"', tmp_path)

    assert artifacts_from_python_deps(deps, marker_environment={"python_version": "3.12"}) == []


def test_constraint_changes_local_find_links_selection(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "demo-1.0-py3-none-any.whl"
    wheel.write_bytes(b"not a real wheel, but enough for filename and digest resolution")
    constraints_file = tmp_path / "constraints.txt"
    constraints_file.write_text("demo!=1.0\n")
    deps = PythonDeps(f"--find-links {wheelhouse}\ndemo==1.0\n", tmp_path)
    constraints = PythonConstraints("constraints.txt", tmp_path)

    artifacts = artifacts_from_python_deps(deps, constraints, {"python_version": "3.12"})

    assert len(artifacts) == 1
    assert artifacts[0].source == "unresolved:index-or-other-remote-source"
    assert artifacts[0].issues

    constraints_file.write_text("demo<=1.0\n")
    constraints = PythonConstraints("constraints.txt", tmp_path)
    artifacts = artifacts_from_python_deps(deps, constraints, {"python_version": "3.12"})

    assert len(artifacts) == 1
    assert artifacts[0].filename == wheel.name
    assert artifacts[0].sha256
