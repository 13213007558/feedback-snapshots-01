from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent
REPO_ROOT = DEMO.parents[1]
sys.path.insert(0, str(DEMO))

from portal import ApprovalPolicy, AuditLog, PortalGateway  # noqa: E402
from portal.policy import Baseline  # noqa: E402


@pytest.fixture
def portal_project(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A writable copy of the portal project plus the shared wheelhouse."""
    project = tmp_path / "portal_demo"
    shutil.copytree(DEMO / "portal_demo", project, ignore=shutil.ignore_patterns(".tox"))
    wheelhouse = tmp_path / "wheelhouse"
    shutil.copytree(DEMO / "wheelhouse", wheelhouse)
    # The manifest content hashes are irrelevant to the gateway decisions under test.
    baseline_manifest = tmp_path / "baseline.json"
    shutil.copy(DEMO / "baseline.json", baseline_manifest)
    return project, wheelhouse, baseline_manifest


@pytest.fixture
def gateway(portal_project: tuple[Path, Path, Path], tmp_path: Path) -> PortalGateway:
    project, _wheelhouse, baseline_manifest = portal_project
    audit = AuditLog(tmp_path / "audit.json")
    policy = ApprovalPolicy(Baseline.load(portal_project[1], baseline_manifest))
    tox_binary = REPO_ROOT / ".venv" / "bin" / "tox"
    return PortalGateway(project, "tox.toml", policy, audit, tox_binary=str(tox_binary))


@pytest.fixture
def policy(gateway: PortalGateway) -> ApprovalPolicy:
    return gateway._policy  # noqa: SLF001 - test access to the decision store


@pytest.fixture
def audit(gateway: PortalGateway) -> AuditLog:
    return gateway._audit  # noqa: SLF001 - test access to the audit trail
