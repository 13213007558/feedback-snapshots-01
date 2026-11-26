"""Audit trail recording the actual installer and interpreter invocations.

Every external command the portal launches through tox is recorded with its
argv, phase and outcome. The report distinguishes the three portal states and
makes it provable that an unapproved version never launched a project command.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class CallRecord:
    phase: str
    argv: tuple[str, ...]
    cwd: str
    exit_code: int
    stdin_summary: str | None = None
    note: str = ""

    @property
    def command_line(self) -> str:
        return shlex.join(self.argv)


@dataclass(slots=True)
class AuditLog:
    path: Path
    calls: list[CallRecord] = field(default_factory=list)

    def record(self, record: CallRecord) -> None:
        self.calls.append(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(call) for call in self.calls], indent=2) + "\n", encoding="utf-8")

    def run(
        self,
        phase: str,
        argv: Sequence[str],
        cwd: Path,
        *,
        note: str = "",
        stdin_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Invoke a command, recording the exact argv and outcome first."""
        completed = subprocess.run(  # noqa: S603 - argv is fully portal-controlled
            list(argv),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            input=stdin_text,
            check=False,
        )
        self.record(
            CallRecord(
                phase=phase,
                argv=tuple(argv),
                cwd=str(cwd),
                exit_code=completed.returncode,
                stdin_summary=None if stdin_text is None else f"{len(stdin_text)} chars via stdin",
                note=note,
            )
        )
        return completed

    def install_calls(self) -> list[CallRecord]:
        return [call for call in self.calls if "install" in " ".join(call.argv)]

    def project_command_calls(self) -> list[CallRecord]:
        return [call for call in self.calls if call.phase in {"execute", "project-command"}]

    def harvest_tox_logs(self, env_log_dir: Path) -> list[CallRecord]:
        """Read tox's per-command execute logs into the audit trail.

        tox launches the installer (``python -m pip install ...``) and the
        project command (``python <script>``) as child processes and writes one
        log per call. Harvesting them records the actual interpreter argv,
        which the outer tox wrapper invocation does not expose.
        """
        harvested: list[CallRecord] = []
        if not env_log_dir.is_dir():
            return harvested
        for log_file in sorted(env_log_dir.glob("*.log")):
            run_id = ""
            cmd = ""
            exit_code = -1
            for line in log_file.read_text(encoding="utf-8", errors="backslashreplace").splitlines():
                if line.startswith("run_id: "):
                    run_id = line.removeprefix("run_id: ")
                elif line.startswith("cmd: "):
                    cmd = line.removeprefix("cmd: ")
                elif line.startswith("exit_code: "):
                    exit_code = int(line.removeprefix("exit_code: "))
            if not cmd:
                continue
            phase = "installer" if "install" in run_id else "project-command"
            record = CallRecord(
                phase=phase,
                argv=tuple(shlex.split(cmd)),
                cwd=str(log_file),
                exit_code=exit_code,
                note=f"tox execute log {log_file.name} (run_id={run_id})",
            )
            harvested.append(record)
            self.record(record)
        return harvested

    def as_dict(self) -> list[dict[str, Any]]:
        return [asdict(call) for call in self.calls]
