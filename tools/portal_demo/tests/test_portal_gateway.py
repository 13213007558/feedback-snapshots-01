from __future__ import annotations

import shutil
from pathlib import Path

from portal import ApprovalPolicy, AuditLog, PortalGateway, ScriptContent

DEMO = Path(__file__).resolve().parent.parent
FIXTURES = DEMO / "fixtures"
RUN_ENV = "script-run"


def _write_script(project: Path, fixture: Path) -> ScriptContent:
    target = project / "scripts" / "temp_script.py"
    shutil.copyfile(fixture, target)
    return ScriptContent.read(target)


def test_preview_parses_pep723_summary_without_creating_env(
    gateway: PortalGateway, portal_project: tuple[Path, Path, Path]
) -> None:
    project, _, _ = portal_project
    script = _write_script(project, FIXTURES / "temp_script_pep723.py")

    preview = gateway.preview(script)

    assert preview.state == "parsed"
    assert preview.digest == script.digest
    assert preview.requires_python == ">=3.12"
    assert preview.dependencies == ("setuptools==84.2.1",)
    assert not (project / ".tox").exists(), "preview must not prepare any environment"
    assert all(call.phase == "preview" for call in gateway._audit.calls)  # noqa: SLF001


def test_execution_requires_approval_even_when_env_exists(
    gateway: PortalGateway, portal_project: tuple[Path, Path, Path]
) -> None:
    project, _, _ = portal_project
    script = _write_script(project, FIXTURES / "temp_script_pep723.py")
    gateway.preview(script)

    decision, process = gateway.request_execution(script, RUN_ENV)

    assert not decision.approved
    assert process is None, "unapproved content must never launch tox"
    assert not (project / ".tox" / "script").exists()
    denied = [call for call in gateway._audit.calls if call.phase == "denied"]  # noqa: SLF001
    assert len(denied) == 1
    assert "blocked before process launch" in denied[0].note


def test_approved_execution_installs_and_runs_then_reuses_cache(
    gateway: PortalGateway,
    policy: ApprovalPolicy,
    audit: AuditLog,
    portal_project: tuple[Path, Path, Path],
) -> None:
    project, _, _ = portal_project
    script = _write_script(project, FIXTURES / "temp_script_pep723.py")
    preview = gateway.preview(script)
    policy.grant(script.digest, RUN_ENV, preview.dependencies)

    first_decision, first_run = gateway.request_execution(script, RUN_ENV)
    assert first_decision.approved
    assert first_run is not None and first_run.returncode == 0
    assert "temp-script imported setuptools 84.2.1" in first_run.stdout
    installer = [call for call in audit.calls if call.phase == "installer"]
    assert installer and installer[0].argv[:4] == ("python", "-I", "-m", "pip")
    assert "setuptools==84.2.1" in installer[0].argv
    commands = [call for call in audit.calls if call.phase == "project-command"]
    assert len(commands) == 1 and commands[0].argv[0] == "python"

    # Second approved request reuses the warmed environment: no new installer call.
    _, reuse_run = gateway.request_execution(script, RUN_ENV)
    assert reuse_run is not None and reuse_run.returncode == 0
    assert "install_deps" not in reuse_run.stdout
    assert len([call for call in audit.calls if call.phase == "installer"]) == 1
    assert len([call for call in audit.calls if call.phase == "project-command"]) == 2


def test_new_version_at_same_path_is_previewable_but_blocked_until_reapproved(
    gateway: PortalGateway,
    policy: ApprovalPolicy,
    audit: AuditLog,
    portal_project: tuple[Path, Path, Path],
) -> None:
    project, _, _ = portal_project
    first = _write_script(project, FIXTURES / "temp_script_pep723.py")
    policy.grant(first.digest, RUN_ENV, gateway.preview(first).dependencies)
    decision, run = gateway.request_execution(first, RUN_ENV)
    assert decision.approved and run is not None and run.returncode == 0
    env_dir = project / ".tox" / "script"
    assert env_dir.exists()

    replacement = _write_script(project, FIXTURES / "ordinary_job.py")
    assert replacement.digest != first.digest

    preview = gateway.preview(replacement)
    assert preview.state == "parsed"
    assert preview.dependencies == ()
    assert env_dir.exists(), "previewing a new version must retain the cache"

    denied, blocked_run = gateway.request_execution(replacement, RUN_ENV)
    assert not denied.approved
    assert blocked_run is None
    project_commands_before = len([call for call in audit.calls if call.phase == "project-command"])

    policy.grant(replacement.digest, RUN_ENV, preview.dependencies)
    approved, second_run = gateway.request_execution(replacement, RUN_ENV)
    assert approved.approved
    assert second_run is not None and second_run.returncode == 0
    assert "ordinary-job ran" in second_run.stdout
    project_commands_after = len([call for call in audit.calls if call.phase == "project-command"])
    assert project_commands_after == project_commands_before + 1


def test_dependency_outside_baseline_cannot_be_approved(
    gateway: PortalGateway,
    policy: ApprovalPolicy,
    portal_project: tuple[Path, Path, Path],
) -> None:
    project, _, _ = portal_project
    script = _write_script(project, FIXTURES / "temp_script_pep723.py")
    gateway.preview(script)

    decision = policy.grant(script.digest, RUN_ENV, ("totally-unknown-package==1.0",))
    assert not decision.approved
    assert "baseline" in decision.reason
    _, process = gateway.request_execution(script, RUN_ENV)
    assert process is None


def test_baseline_matches_pep503_normalized_names(
    gateway: PortalGateway,
    policy: ApprovalPolicy,
) -> None:
    assert policy.baseline.allows(["Setuptools==84.2.1"])
    assert policy.baseline.allows(["PIP"])
    assert not policy.baseline.allows(["definitely-missing"])
