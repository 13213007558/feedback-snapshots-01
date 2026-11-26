"""Optional public receipts and private diagnostics of a creation, with the cleanup a failed creation performs.

A public receipt can travel outside the machine that ran the creation, so it names no directory, no file from the
tenant's working tree and no cache location. A private diagnostic keeps those actual paths for controlled operations.
Both documents carry the same random job identifier, so an operator can find the diagnostic without the receipt naming
where it lives.
"""

from __future__ import annotations

__lazy_modules__ = [
    "json",
    "logging",
    "os",
    "pathlib",
    "uuid",
    "virtualenv.util.path",
]

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import uuid4

from virtualenv.util.path import remove_file, safe_delete

if TYPE_CHECKING:
    from collections.abc import Iterator

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)  # simplint: ignore[module-variable-prefix]  # existing name

#: Version written into both documents.
SCHEMA: Final[int] = 1

#: Creation stages, in order, as they appear in the receipt.
STAGES: Final[tuple[str, ...]] = ("create", "seed", "activate", "finalize")

#: A step that finished.
STEP_SUCCEEDED: Final[str] = "succeeded"
#: A step that raised.
STEP_FAILED: Final[str] = "failed"
#: A step that had nothing to do.
STEP_SKIPPED: Final[str] = "skipped"
#: A step that was never reached.
STEP_NOT_STARTED: Final[str] = "not_started"

#: The cleanup reclaimed everything the failed creation introduced.
CLEANUP_COMPLETED: Final[str] = "completed"
#: The failed creation removed its own materials but kept a destination that existed before it started.
CLEANUP_PRESERVED: Final[str] = "preserved"
#: The cleanup could not finish or could not prove ownership, so controlled operations must take over.
CLEANUP_INCOMPLETE: Final[str] = "incomplete"
#: The creation succeeded, so there was nothing to reclaim.
CLEANUP_NOT_REQUIRED: Final[str] = "not_required"

#: Whether the materials left behind need a controlled operator.
HANDOFF_REQUIRED: Final[str] = "required"
HANDOFF_NOT_REQUIRED: Final[str] = "not_required"

_PUBLIC_MODE: Final[int] = 0o644
_PRIVATE_MODE: Final[int] = 0o600


class CreationScope:
    """The materials one creation owns under a managed parent directory.

    The scope snapshots the destination and the sibling ``.venv`` redirect before creation starts, so a failed creation
    reclaims only what it introduced. It never walks the parent directory, so a finished environment another job placed
    beside it is outside this scope by construction.

    :param dest: the destination directory of the creation
    :param receipt_dir: the directory the public receipt is written to, ``None`` to write none
    :param diagnostic_dir: the directory the private diagnostic is written to, ``None`` to write none
    :param defaults_diagnostic: ``True`` when no explicit diagnostic folder was given, so a diagnostic is written
        beside the receipt
    :param clears: ``True`` when ``--clear`` replaced the destination, which makes everything in it this job's

    """

    def __init__(
        self,
        dest: Path,
        receipt_dir: Path | None,
        diagnostic_dir: Path | None,
        *,
        defaults_diagnostic: bool,
        clears: bool,
    ) -> None:
        self.dest = dest
        self.job = uuid4().hex
        self.receipt_dir = receipt_dir
        self.diagnostic_dir = diagnostic_dir
        #: ``True`` when a diagnostic is written beside the receipt by default rather than into an explicit folder
        self.defaults_diagnostic = defaults_diagnostic
        for label, folder in (("receipt", receipt_dir), ("diagnostic", diagnostic_dir)):
            if folder is not None and folder.resolve().is_relative_to(dest.resolve()):
                msg = f"the {label} directory must not be inside the environment {dest}"
                raise ValueError(msg)
        existed = dest.exists() or dest.is_symlink()
        # a symlinked destination is reused through its target rather than deleted, since the link is the pre-existing
        # entry and its target may hold content the job did not create
        self._reuses_symlink = dest.is_symlink()
        # with --clear the original destination was removed already, so whatever is there now belongs to this job
        self._owned_whole = not self._reuses_symlink and (clears or not existed)
        self._prior_entries = None if self._owned_whole else self._snapshot_entries()
        self._redirect = dest.parent / ".venv"
        self._redirect_text = self._read_redirect()
        self.receipt_path: Path | None = None
        self.diagnostic_path: Path | None = None

    def _snapshot_entries(self) -> frozenset[str] | None:
        # a symlinked destination is read through to its target, so only entries this job introduces are removed there
        if not self.dest.is_dir():
            return None
        try:
            return frozenset(entry.name for entry in self.dest.iterdir())
        # an unreadable destination is treated as holding everything, so cleanup removes nothing it cannot inspect
        except OSError:
            return None

    def _read_redirect(self) -> str | None:
        if not self._redirect.is_file() or self._redirect.is_symlink():
            return None
        try:
            return next(iter(self._redirect.read_text(encoding="utf-8").splitlines()), "").strip()
        # an unreadable redirect is treated as foreign, so cleanup leaves it alone
        except (OSError, ValueError):
            return None

    def reclaim(self) -> CleanupReport:
        """Reclaim the materials this creation owns, leaving existing content and another job's output alone.

        :returns: what was removed and what a controlled operator must still handle

        """
        report = CleanupReport()
        self._reclaim_redirect(report)
        if not self.dest.exists() and not self.dest.is_symlink():
            return report
        if self._owned_whole:
            self._reclaim_whole(report)
        elif self._prior_entries is not None:
            self._reclaim_introduced(report)
        else:
            self._escalate(report)
        return report

    def _reclaim_whole(self, report: CleanupReport) -> None:
        try:
            report.removed_entries = _count_entries(self.dest)
            safe_delete(self.dest)
            report.removed.append(str(self.dest))
        except (OSError, RuntimeError) as exception:
            report.state = CLEANUP_INCOMPLETE
            report.error = exception
            report.retained.append(str(self.dest))
            LOGGER.warning("could not reclaim the destination because %r", exception)

    def _reclaim_introduced(self, report: CleanupReport) -> None:
        prior = self._prior_entries or frozenset()
        try:
            if not self.dest.is_dir():
                self._escalate(report)
                return
            for entry in self.dest.iterdir():
                if entry.name in prior:
                    continue
                report.removed_entries += _count_entries(entry)
                _remove(entry)
                report.removed.append(str(entry))
        except (OSError, RuntimeError) as exception:
            report.state = CLEANUP_INCOMPLETE
            report.error = exception
            report.retained.append(str(self.dest))
            LOGGER.warning("could not reclaim the parts this creation owns because %r", exception)
            return
        # the destination existed before this job and stays usable, so a later creation can reuse it
        report.state = CLEANUP_PRESERVED

    def _escalate(self, report: CleanupReport) -> None:
        report.state = CLEANUP_INCOMPLETE
        report.retained.append(str(self.dest))
        LOGGER.warning(
            "cannot prove which materials this creation owns in %s, leaving them for an operator",
            self.dest,
        )

    def _reclaim_redirect(self, report: CleanupReport) -> None:
        # the redirect is only this job's to reclaim while it points at this destination
        if not self._redirect.is_file() or self._redirect.is_symlink():
            return
        try:
            current = self._redirect.read_text(encoding="utf-8").splitlines()[:1]
        # a redirect that cannot be read is left for an operator, who can still inspect the diagnostic
        except (OSError, ValueError):
            return
        if current != [self.dest.name]:
            return
        if self._redirect_text == self.dest.name:
            # pre-existing redirect that already pointed here, so it is not this job's to change
            return
        try:
            if self._redirect_text is not None:
                # another job's redirect was there first; this job replaced it, so put the earlier one back
                self._redirect.write_text(f"{self._redirect_text}\n", encoding="utf-8")
                report.restored.append(str(self._redirect))
            else:
                self._redirect.unlink()
                report.removed.append(str(self._redirect))
        # a redirect that cannot be restored or removed is reported with the rest of the retained materials
        except OSError as exception:
            report.state = CLEANUP_INCOMPLETE
            report.error = exception
            report.retained.append(str(self._redirect))


class CleanupReport:
    """The result of reclaiming a failed creation's materials."""

    def __init__(self) -> None:
        self.state: str = CLEANUP_COMPLETED
        self.removed_entries: int = 0
        self.removed: list[str] = []
        self.restored: list[str] = []
        self.retained: list[str] = []
        self.error: BaseException | None = None


class CreationRecord:
    """The facts of one creation, kept so a failure can still produce a receipt.

    :param scope: the materials this creation owns
    :param interpreter: the interpreter description, as ``implementation`` and ``version``
    :param environ_name: the environment name, only used privately

    """

    def __init__(self, scope: CreationScope, interpreter: dict[str, str], environ_name: str) -> None:
        self.scope = scope
        self.interpreter = interpreter
        self.environ_name = environ_name
        self.steps: dict[str, str] = {stage: STEP_NOT_STARTED for stage in STAGES}
        self.current: str | None = None
        self.seeded: list[str] = []
        self.failure: BaseException | None = None

    def begin(self, stage: str) -> None:
        """Mark a stage as running."""
        self.current = stage

    def finish(self, stage: str) -> None:
        """Mark a stage as completed."""
        self.steps[stage] = STEP_SUCCEEDED
        self.current = None

    def skip(self, stage: str) -> None:
        """Mark a stage as having nothing to do."""
        self.steps[stage] = STEP_SKIPPED
        self.current = None

    def fail(self, exception: BaseException) -> None:
        """Record the exception that stopped the creation in the running stage."""
        if self.failure is None:
            self.failure = exception
        if self.current is not None:
            self.steps[self.current] = STEP_FAILED
            self.current = None

    def public_document(self, cleanup: CleanupReport) -> dict[str, Any]:
        """Build the path-free receipt that may leave the machine."""
        needs_operator = cleanup.state == CLEANUP_INCOMPLETE
        cleaned = cleanup.state in {
            CLEANUP_COMPLETED,
            CLEANUP_PRESERVED,
            CLEANUP_NOT_REQUIRED,
        }
        return {
            "schema": SCHEMA,
            "job": self.scope.job,
            "interpreter": dict(self.interpreter),
            "outcome": STEP_FAILED if self.failure is not None else STEP_SUCCEEDED,
            "steps": dict(self.steps),
            "cleanup": {
                "state": cleanup.state,
                "cleaned": cleaned,
                "removed_entries": cleanup.removed_entries,
            },
            "handoff": HANDOFF_REQUIRED if needs_operator else HANDOFF_NOT_REQUIRED,
            "evidence_retained": self.scope.diagnostic_dir is not None,
            # The exception kind is safe to share; its message may name a real path, so it stays in the diagnostic.
            "error": None if self.failure is None else {"kind": type(self.failure).__name__},
        }

    def diagnostic_document(self, cleanup: CleanupReport) -> dict[str, Any]:
        """Build the private diagnostic that names the actual files for controlled operations."""
        return {
            "schema": SCHEMA,
            "job": self.scope.job,
            "destination": str(self.scope.dest),
            "environment": self.environ_name,
            "interpreter": dict(self.interpreter),
            "steps": dict(self.steps),
            "seeded": list(self.seeded),
            "error": None if self.failure is None else _exception_details(self.failure),
            "cleanup": {
                "state": cleanup.state,
                "removed_entries": cleanup.removed_entries,
                "removed": list(cleanup.removed),
                "restored": list(cleanup.restored),
                "retained": list(cleanup.retained),
                "error": None if cleanup.error is None else _exception_details(cleanup.error),
            },
        }


def _exception_details(exception: BaseException) -> dict[str, Any]:
    return {"kind": type(exception).__name__, "message": str(exception)}


def write_documents(record: CreationRecord, cleanup: CleanupReport) -> None:
    """Write the public receipt and, when requested, the private diagnostic.

    A document that cannot be written is logged, not raised, so an optional receipt never hides the creation result.

    :param record: the recorded facts of the creation
    :param cleanup: the outcome of reclaiming a failed creation, or a completed report on success

    """
    scope = record.scope
    if scope.receipt_dir is not None:
        name = scope.receipt_dir / f"receipt-{scope.job}.json"
        scope.receipt_path = _write(name, record.public_document(cleanup), _PUBLIC_MODE)
    if scope.diagnostic_dir is not None:
        diagnostic = record.diagnostic_document(cleanup)
        diagnostic["receipt"] = None if scope.receipt_path is None else str(scope.receipt_path)
        scope.diagnostic_path = _write(
            scope.diagnostic_dir / f"diagnostic-{scope.job}.json",
            diagnostic,
            _PRIVATE_MODE,
        )


def _write(path: Path, content: dict[str, Any], mode: int) -> Path | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # a random staging name, so two jobs writing into one directory never stage over each other
        staging = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (os.O_BINARY if os.name == "nt" else 0)
        with os.fdopen(os.open(str(staging), flags, mode), "w", encoding="utf-8") as stream:
            stream.write(json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False))
            stream.write("\n")
        # the explicit mode above is the contract: the document may travel, but its private sibling has the tighter bit
        os.chmod(str(staging), mode)
        os.replace(str(staging), str(path))
    # a receipt the caller asked for is optional, so its failure must not replace the creation result
    except (OSError, TypeError) as exception:
        LOGGER.warning("could not write %s because %r", path, exception)
        return None
    return path


def _remove(path: Path) -> None:
    # a top-level entry can be a file or a symlink, which safe_delete does not handle
    if path.is_symlink() or not path.is_dir():
        remove_file(path)
    else:
        safe_delete(path)


def _count_entries(root: Path) -> int:
    count = 0
    for _ in _walk(root):
        count += 1
    return count


def _walk(root: Path) -> Iterator[Path]:
    yield root
    for base, dirs, files in os.walk(str(root), followlinks=False):
        yield from (Path(base) / name for name in files)
        yield from (Path(base) / name for name in dirs)


__all__ = [
    "CLEANUP_COMPLETED",
    "CLEANUP_INCOMPLETE",
    "CLEANUP_NOT_REQUIRED",
    "CLEANUP_PRESERVED",
    "HANDOFF_NOT_REQUIRED",
    "HANDOFF_REQUIRED",
    "STEP_FAILED",
    "STEP_NOT_STARTED",
    "STEP_SKIPPED",
    "STEP_SUCCEEDED",
    "CreationRecord",
    "CreationScope",
    "CleanupReport",
    "write_documents",
]
