"""Fan one release out to several targets with independent failure domains.

There is deliberately **no** attempt at a distributed transaction here:
independent write targets cannot be made atomically all-succeed.  The
landable pattern is per-target staging/generation + verification, then a
control-plane release pointer.  :func:`fanout` runs each target job and keeps
its outcome or exception isolated, so the platform can retry only the failed
target using that target's own recovery procedure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from deploy_demo.verify import VerificationReport


@dataclass
class TargetResult:
    """Outcome for one named target."""

    name: str
    ok: bool
    verification: VerificationReport | None = None
    error_type: str | None = None
    error: str | None = None


def fanout(jobs: dict[str, Callable[[], object]]) -> list[TargetResult]:
    """Run named deployment jobs, capturing exceptions per target."""
    results: list[TargetResult] = []
    for name, job in jobs.items():
        try:
            outcome = job()
        except Exception as exc:  # boundary: isolate target failures
            results.append(
                TargetResult(
                    name=name,
                    ok=False,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            )
            continue
        verification = getattr(outcome, "verification", None)
        results.append(
            TargetResult(
                name=name,
                ok=True,
                verification=verification
                if isinstance(verification, VerificationReport)
                else None,
            )
        )
    return results
