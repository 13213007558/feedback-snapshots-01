"""End-to-end scenario for the cloud build portal's staged script pipeline.

Sequence (script path never changes; only its content is swapped):

1. Preview a temporary PEP 723 script -> parsed summary, no environment.
2. Administrator approves its content + the run environment; execute it,
   which warms the cached environment (installed -> executed).
3. Replace the file in place with an ordinary script. Re-preview (still
   parsed, cache retained) and request execution without approval for the new
   content -> the project command is never launched.

All installer/interpreter invocations land in ``reports/audit.json``.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
TOX_BINARY = REPO_ROOT / ".venv" / "bin" / "tox"
sys.path.insert(0, str(HERE))

from portal import ApprovalPolicy, AuditLog, PortalGateway, ScriptContent  # noqa: E402

PROJECT = HERE / "portal_demo"
SCRIPT = PROJECT / "scripts" / "temp_script.py"
ORIGINAL = HERE / "fixtures" / "temp_script_pep723.py"
REPLACEMENT = HERE / "fixtures" / "ordinary_job.py"
REPORTS = HERE / "reports"
RUN_ENV = "script-run"


def _heading(text: str) -> None:
    print(f"\n=== {text} ===")


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    for stale in REPORTS.glob("*"):
        stale.unlink()
    shutil.rmtree(PROJECT / ".tox", ignore_errors=True)

    audit = AuditLog(REPORTS / "audit.json")
    from portal.policy import Baseline

    policy = ApprovalPolicy(Baseline.load(HERE / "wheelhouse", HERE / "baseline.json"))
    gateway = PortalGateway(PROJECT, "tox.toml", policy, audit, tox_binary=str(TOX_BINARY))

    _heading("phase 1: preview temporary PEP 723 script (parse only)")
    shutil.copyfile(ORIGINAL, SCRIPT)
    first = ScriptContent.read(SCRIPT)
    preview_one = gateway.preview(first)
    print(json.dumps(preview_one.as_dict(), indent=2))
    assert not (PROJECT / ".tox").exists(), "preview must not create an environment"

    _heading("phase 2: approve content + environment, then execute and warm the cache")
    decision = policy.grant(first.digest, RUN_ENV, preview_one.dependencies)
    print(f"approval: approved={decision.approved} reason={decision.reason!r}")
    approved_decision, first_run = gateway.request_execution(first, RUN_ENV)
    assert first_run is not None and first_run.returncode == 0, first_run.stderr
    print(first_run.stdout.strip())
    env_dir = PROJECT / ".tox" / "script"
    assert env_dir.exists(), "execution should have warmed the shared environment"

    _heading("phase 2b: re-request the approved content -> cache reuse, no installer")
    _, reuse_run = gateway.request_execution(first, RUN_ENV)
    assert reuse_run is not None and reuse_run.returncode == 0, reuse_run.stderr
    assert "install_deps" not in reuse_run.stdout, "reused environment must not reinstall"
    print(reuse_run.stdout.strip())

    _heading("phase 3a: swap in an ordinary script at the same path, keep the cache")
    shutil.copyfile(REPLACEMENT, SCRIPT)
    second = ScriptContent.read(SCRIPT)
    assert second.digest != first.digest, "new content must produce a new digest"
    preview_two = gateway.preview(second)
    print(json.dumps(preview_two.as_dict(), indent=2))
    assert env_dir.exists(), "previewing a new version must retain the cached environment"

    _heading("phase 3b: request execution for the unapproved new version")
    denied_decision, second_run = gateway.request_execution(second, RUN_ENV)
    assert not denied_decision.approved
    assert second_run is None, "no process may launch for unapproved content"
    print(f"blocked: {denied_decision.reason!r} (env reuse attempted={env_dir.exists()})")

    _heading("phase 3c: grant approval for the new content, then execute via reuse")
    policy.grant(second.digest, RUN_ENV, preview_two.dependencies)
    _, approved_second_run = gateway.request_execution(second, RUN_ENV)
    assert approved_second_run is not None and approved_second_run.returncode == 0, approved_second_run.stderr
    print(approved_second_run.stdout.strip())

    _heading("audit evidence")
    summary = {
        "states": {
            "parsed": [preview_one.digest[:12], preview_two.digest[:12]],
            "installed": [call.command_line for call in audit.calls if call.phase == "installer"],
            "executed": [call.command_line for call in audit.calls if call.phase == "project-command"],
        },
        "total_calls": len(audit.calls),
        "installer_calls": [call.command_line for call in audit.install_calls()],
        "interpreter_project_commands": [
            call.command_line for call in audit.calls if call.phase == "project-command"
        ],
        "denied_without_launch": [call.note for call in audit.calls if call.phase == "denied"],
    }
    print(json.dumps(summary, indent=2))
    (REPORTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\nfull audit trail: {audit.path}")
    shutil.copyfile(ORIGINAL, SCRIPT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
