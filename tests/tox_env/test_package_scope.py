from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from tox.tox_env.package_scope import (
    BuildCapabilityDenied,
    PackageBuildScope,
    PackagePreparation,
    PackageReuseContract,
    PackageReuseDenied,
    ScopedArtifact,
)

WIDE = PackageBuildScope.create(
    approved=["local-record", "network"],
    factors={"package": "wheel", "backend": "fake-local-builder"},
)
NARROW = PackageBuildScope.create(
    approved=["local-record"],
    factors={"package": "wheel", "backend": "fake-local-builder"},
)


class FakeLocalPackageBuilder:
    def __init__(self, contract: PackageReuseContract, dist_dir: Path) -> None:
        self.contract = contract
        self.dist_dir = dist_dir
        self.calls: list[str] = []

    def build(
        self,
        preparation: PackagePreparation,
        *,
        used: tuple[str, ...] = ("local-record",),
        contents: bytes | None = None,
    ) -> ScopedArtifact:
        index = len(self.calls) + 1
        self.contract.authorize_build(preparation, used)
        name = preparation.name
        scope_key = preparation.scope.fingerprint[:12]
        call = f"build_wheel[{index}]:{name}:{scope_key}"
        self.calls.append(call)
        artifact_path = self.dist_dir / f"{name}-{index}.whl"
        artifact_path.write_bytes(contents or f"{call}\n".encode())
        return self.contract.record_build(
            preparation,
            artifact_path,
            used=used,
            calls=[call],
            builder="fake-local-builder",
        )


def test_same_name_different_approvals_are_separate_preparations(tmp_path: Path) -> None:
    contract = PackageReuseContract()

    wide = contract.prepare("demo", WIDE)
    narrow = contract.prepare("demo", NARROW)

    assert wide.key != narrow.key
    assert list(contract.preparations) == [wide.key, narrow.key]

    builder = FakeLocalPackageBuilder(contract, tmp_path)
    wide_artifact = builder.build(wide, used=("network", "local-record"), contents=b"wide")

    denied = contract.check_reuse("demo", NARROW)
    assert denied.status == "denied"
    assert denied.artifact is None
    assert denied.out_of_scope == frozenset({"network"})

    with pytest.raises(PackageReuseDenied):
        contract.request_reuse("restricted", "demo", NARROW)

    narrow_run = contract.begin_run("restricted-build", "demo", NARROW)
    assert narrow_run.decision.status == "denied"
    narrow_artifact = builder.build(narrow, contents=b"narrow")

    assert wide_artifact.digest == sha256(b"wide").hexdigest()
    assert narrow_artifact.digest == sha256(b"narrow").hexdigest()
    assert wide_artifact.digest != narrow_artifact.digest
    assert len(builder.calls) == 2

    next_narrow_run = contract.begin_run("restricted-test", "demo", NARROW)
    assert next_narrow_run.reused is True
    assert next_narrow_run.artifact is not None
    assert next_narrow_run.artifact.digest == narrow_artifact.digest
    assert "restricted" in contract.report()["conflicts"]
    assert {run.env_name for run in contract.conflicts} >= {"restricted", "restricted-build"}


def test_artifact_that_actually_uses_only_narrow_capabilities_can_reuse(tmp_path: Path) -> None:
    contract = PackageReuseContract()
    builder = FakeLocalPackageBuilder(contract, tmp_path)
    wide = contract.prepare("demo", WIDE)
    wide_artifact = builder.build(wide, used=("local-record",), contents=b"same-local-output")

    decision = contract.check_reuse("demo", NARROW)

    assert decision.status == "reused"
    assert decision.reason == "build-evidence-within-scope"
    assert decision.artifact is not None
    assert decision.artifact.digest == wide_artifact.digest


def test_two_equal_scope_runs_share_one_build_and_artifact(tmp_path: Path) -> None:
    contract = PackageReuseContract()
    builder = FakeLocalPackageBuilder(contract, tmp_path)
    scope = PackageBuildScope.create(approved=["local-record"], factors={"package": "wheel"})

    decision_before_build = contract.check_reuse("shared-demo", scope)
    assert decision_before_build.status == "build_required"

    preparation = contract.prepare("shared-demo", scope)
    artifact = builder.build(preparation, contents=b"shared")
    first = contract.begin_run("py312-a", "shared-demo", scope)
    second = contract.begin_run("py312-b", "shared-demo", scope)

    assert first.reused is True
    assert second.reused is True
    assert first.artifact is not None
    assert second.artifact is not None
    assert first.artifact.path == artifact.path
    assert second.artifact.path == artifact.path
    assert first.artifact.digest == artifact.digest
    assert second.artifact.digest == artifact.digest
    assert len(builder.calls) == 1
    assert [run.env_name for run in contract.runs] == ["py312-a", "py312-b"]


def test_build_cannot_exceed_preparation_approval(tmp_path: Path) -> None:
    contract = PackageReuseContract()
    builder = FakeLocalPackageBuilder(contract, tmp_path)
    narrow = contract.prepare("demo", NARROW)

    with pytest.raises(BuildCapabilityDenied) as exc_info:
        builder.build(narrow, used=("network",))

    assert exc_info.value.denied == frozenset({"network"})
    assert builder.calls == []
