"""A staging :class:`WheelDestination` with explicit abort/commit/rollback.

Everything ``installer.install`` writes goes into a fresh generation
directory::

    <stage_root>/<generation>/<scheme>/<in-scheme-path>

The live scheme directories are untouched until :meth:`commit`, which promotes
files with :func:`os.replace` (atomic per file on one filesystem).  Files that
would be overwritten are moved aside first, so a failed mid-commit promotion
can be rolled back to the exact previous tree.

Recovery matrix
---------------
* read/write failure during ``install``  -> ``abort()`` discards the generation;
  the live tree never changed; retry with a new generation.
* process crash during staging           -> an orphan ``<generation>`` dir is
  left behind; a janitor removes stale generations; live tree untouched.
* failure during ``commit``              -> commit rolls back automatically
  using the per-transaction backup; live tree equals the pre-commit snapshot.
* process crash during ``commit``        -> ``journal.json`` describes the
  transaction; an operator/reconciler finishes or reverses it.

This is per-target recoverability only.  Several independent targets can **not**
be made atomically committable together; fan-out recovery is "retry the failed
target", not a distributed transaction.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from installer.destinations import SchemeDictionaryDestination

from deploy_demo.errors import CommitFailed
from deploy_demo.paths import safe_resolve


@dataclass(frozen=True)
class Promotion:
    """One staged-file -> live-file replacement."""

    staged: Path
    live: Path
    backup: Path


@dataclass
class CommitReport:
    """Outcome of a successful staging commit."""

    generation: str
    promoted: list[Path]
    backups: list[Path]
    transaction_dir: Path


def new_generation_id() -> str:
    """Return a short unique generation identifier."""
    return uuid.uuid4().hex[:12]


class StagingWheelDestination(SchemeDictionaryDestination):
    """Write into a generation-scoped stage dir; promote on ``commit``."""

    def __init__(
        self,
        *,
        final_scheme_dict: dict[str, str | os.PathLike[str]],
        stage_root: str | os.PathLike[str],
        generation: str | None = None,
        interpreter: str = "/usr/bin/python3",
        script_kind: str = "posix",
        hash_algorithm: str = "sha256",
    ) -> None:
        self.generation = generation or new_generation_id()
        self.stage_root = Path(stage_root)
        self.stage_dir = self.stage_root / self.generation
        self.transaction_dir = self.stage_root / "_transactions" / self.generation
        self.final_scheme_dict = {
            str(scheme): Path(path) for scheme, path in final_scheme_dict.items()
        }
        staged_scheme_dict = {
            scheme: str(self.stage_dir / scheme) for scheme in final_scheme_dict
        }
        super().__init__(
            scheme_dict=staged_scheme_dict,
            interpreter=interpreter,
            script_kind=script_kind,  # type: ignore[arg-type]
            hash_algorithm=hash_algorithm,
            overwrite_existing=False,
        )
        self.aborted = False
        self.committed = False
        self.commit_report: CommitReport | None = None

    def abort(self) -> None:
        """Discard the staged generation. Safe to call once after failure."""
        if self.committed:
            raise CommitFailed("cannot abort a committed staging destination")
        if self.stage_dir.exists():
            shutil.rmtree(self.stage_dir)
        self.aborted = True

    def _nearest_existing_ancestor(self, path: Path) -> Path:
        candidate = path
        while not candidate.exists() and candidate != candidate.parent:
            candidate = candidate.parent
        return candidate

    def _check_same_filesystem(self) -> None:
        stage_anchor = self._nearest_existing_ancestor(self.stage_root)
        stage_dev = stage_anchor.stat().st_dev
        for scheme, root in self.final_scheme_dict.items():
            anchor = self._nearest_existing_ancestor(root)
            if anchor.stat().st_dev != stage_dev:
                raise CommitFailed(
                    f"stage_root {self.stage_root!s} and {scheme} root {root!s} "
                    "are on different filesystems; os.replace() promotion would "
                    "not be atomic. Put stage_root on the target filesystem."
                )

    def _build_promotions(self) -> list[Promotion]:
        if not self.stage_dir.exists():
            return []
        promotions: list[Promotion] = []
        for staged in sorted(p for p in self.stage_dir.rglob("*") if p.is_file()):
            relative = staged.relative_to(self.stage_dir)
            scheme = relative.parts[0]
            if scheme not in self.final_scheme_dict:
                raise CommitFailed(
                    f"staged file {staged!s} uses unknown scheme {scheme!r}"
                )
            inner = Path(*relative.parts[1:])
            live = safe_resolve(self.final_scheme_dict[scheme], inner.as_posix())
            backup = self.transaction_dir / "backup" / relative
            promotions.append(Promotion(staged=staged, live=live, backup=backup))
        return promotions

    def commit(self) -> CommitReport:
        """Atomically-ish promote every staged file into the live tree.

        Per-file replacements are atomic.  If any promotion fails, all
        replacements performed so far are reversed using the backup copies,
        leaving the live tree as it was before ``commit``.
        """
        if self.aborted:
            raise CommitFailed("cannot commit an aborted staging destination")
        if self.committed:
            assert self.commit_report is not None
            return self.commit_report

        self._check_same_filesystem()
        promotions = self._build_promotions()
        self.transaction_dir.mkdir(parents=True, exist_ok=True)
        journal = self.transaction_dir / "journal.json"
        journal.write_text(
            json.dumps(
                [
                    {
                        "staged": str(p.staged),
                        "live": str(p.live),
                        "backup": str(p.backup),
                    }
                    for p in promotions
                ],
                indent=2,
            ),
            encoding="utf-8",
        )

        processed: list[tuple[Promotion, bool]] = []
        try:
            for promotion in promotions:
                promotion.backup.parent.mkdir(parents=True, exist_ok=True)
                if promotion.live.exists() or promotion.live.is_symlink():
                    os.replace(promotion.live, promotion.backup)
                processed.append((promotion, False))  # mutation started
                promotion.live.parent.mkdir(parents=True, exist_ok=True)
                os.replace(promotion.staged, promotion.live)
                processed[-1] = (promotion, True)  # forward replace succeeded
        except OSError as exc:
            rollback_problems = self._rollback(processed)
            raise CommitFailed(
                f"staging commit failed ({exc!r}); "
                f"rollback problems: {rollback_problems or 'none'}"
            ) from exc

        self.committed = True
        report = CommitReport(
            generation=self.generation,
            promoted=[p.live for p in promotions],
            backups=[p.backup for p, _ in processed if p.backup.exists()],
            transaction_dir=self.transaction_dir,
        )
        (self.transaction_dir / "committed.json").write_text(
            json.dumps(
                {
                    "generation": self.generation,
                    "promoted": [str(p) for p in report.promoted],
                    "backups": [str(p) for p in report.backups],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.commit_report = report
        return report

    def _rollback(self, processed: list[tuple[Promotion, bool]]) -> list[str]:
        problems: list[str] = []
        for promotion, forward_ok in reversed(processed):
            try:
                if forward_ok:
                    if promotion.backup.exists():
                        os.replace(promotion.backup, promotion.live)
                    else:
                        promotion.live.unlink(missing_ok=True)
                elif promotion.backup.exists():
                    # Old file was moved aside, but the new one never landed.
                    os.replace(promotion.backup, promotion.live)
            except OSError as exc:  # pragma: no cover - defensive
                problems.append(f"{promotion.live}: {exc!r}")
        return problems
