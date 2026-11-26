"""Portal gateway: parse-only previews and approval-gated execution.

Phases
------
1. ``preview`` parses the script with tox's own PEP 723 metadata parser and
   runs ``tox config`` for the preview environment. Neither step creates a
   virtual environment or launches a project command.
2. An administrator grants an execution approval bound to the content digest
   and the selected environment.
3. ``request_execution`` re-checks the approval (even when the environment
   already exists on disk) and only then runs tox, which creates or reuses the
   warmed environment and executes the script.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tox.tox_env.python.pep723 import _parse_script_metadata  # noqa: PLC2701 - reuse tox's own parser

from .audit import AuditLog, CallRecord
from .policy import ApprovalDecision, ApprovalPolicy, sha256_text

if TYPE_CHECKING:
    from subprocess import CompletedProcess

PREVIEW_ENV = "script-preview"
RUN_ENV = "script-run"


def _default_tox_binary() -> str:
    """Locate the tox console script next to the running interpreter.

    A venv interpreter may be a symlink to a base Python, so ``sys.executable``
    does not always point inside the venv bin directory.
    """
    candidate = Path(sys.executable).resolve().parent / "tox"
    if candidate.exists():
        return str(candidate)
    on_path = shutil.which("tox")
    if on_path is not None:
        return on_path
    msg = "could not locate a tox executable next to the interpreter or on PATH"
    raise FileNotFoundError(msg)


@dataclass(frozen=True, slots=True)
class ScriptContent:
    path: Path
    text: str
    digest: str

    @classmethod
    def read(cls, path: Path) -> ScriptContent:
        text = path.read_text(encoding="utf-8-sig")
        return cls(path=path.resolve(), text=text, digest=sha256_text(text))


@dataclass(frozen=True, slots=True)
class Preview:
    """The dependency summary the portal shows before any approval."""

    path: str
    digest: str
    requires_python: str | None
    dependencies: tuple[str, ...]
    state: str = field(default="parsed")

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.digest,
            "requires-python": self.requires_python,
            "dependencies": list(self.dependencies),
            "state": self.state,
        }


class PortalGateway:
    def __init__(
        self,
        project_dir: Path,
        config_name: str,
        policy: ApprovalPolicy,
        audit: AuditLog,
        tox_binary: str | None = None,
    ) -> None:
        self._project_dir = project_dir.resolve()
        self._config_name = config_name
        self._policy = policy
        self._audit = audit
        self._tox = tox_binary or _default_tox_binary()

    def preview(self, script: ScriptContent) -> Preview:
        """Phase 1: parse and summarize without preparing or executing."""
        metadata = _parse_script_metadata(script.text)
        summary = Preview(
            path=str(script.path),
            digest=script.digest,
            requires_python=metadata.requires_python,
            dependencies=tuple(metadata.dependencies),
        )
        # tox config only loads configuration; --no-provision guarantees it
        # neither creates the provision env nor any target environment.
        completed = self._audit.run(
            "preview",
            [
                self._tox,
                "config",
                "--no-provision",
                "-c",
                self._config_name,
                "-e",
                PREVIEW_ENV,
                "--core",
            ],
            self._project_dir,
            note="configuration load only; no environment is created",
        )
        if completed.returncode != 0:
            msg = f"tox config failed: {completed.stderr.strip() or completed.stdout.strip()}"
            raise RuntimeError(msg)
        return summary

    def request_execution(
        self,
        script: ScriptContent,
        environment: str,
        *,
        reuse_existing: bool = True,
    ) -> tuple[ApprovalDecision, CompletedProcess[str] | None]:
        """Phase 3: execute only when content + environment are approved.

        The same decision runs whether the environment directory exists or not,
        so reusing a warmed cache cannot bypass the gate.
        """
        metadata = _parse_script_metadata(script.text)
        decision = self._policy.evaluate(
            script.digest,
            environment,
            tuple(metadata.dependencies),
        )
        if not decision.approved:
            self._audit.record(
                self._denied_record(script, environment, decision.reason, reuse_existing),
            )
            return decision, None

        argv = [self._tox, "run", "-c", self._config_name, "-e", environment]
        if not reuse_existing:
            argv.insert(4, "--recreate")
        completed = self._audit.run(
            "execute",
            argv,
            self._project_dir,
            note="approved execution; tox reuses the env when present",
        )
        if completed.returncode == 0:
            self._audit.harvest_tox_logs(self._project_dir / ".tox" / environment / "log")
        return decision, completed

    def _denied_record(
        self,
        script: ScriptContent,
        environment: str,
        reason: str,
        reuse_existing: bool,
    ) -> CallRecord:
        return CallRecord(
            phase="denied",
            argv=("tox", "run", "-c", self._config_name, "-e", environment),
            cwd=str(self._project_dir),
            exit_code=126,
            note=f"blocked before process launch ({'reuse' if reuse_existing else 'create'}): {reason}",
            stdin_summary=script.digest,
        )
