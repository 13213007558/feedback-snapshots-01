"""Job-scoped access policy.

Several team jobs share one Lambda execution environment. Each job registers the
parameter paths it is allowed to read; the policy is the single place that decides
whether a name or a batch path is inside the job's boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class JobAccessDeniedError(PermissionError):
    """Raised when a job asks for a parameter path it did not register."""


@dataclass(frozen=True)
class JobAccessPolicy:
    """Allow-list of parameter paths a single job may read.

    A path authorizes the path itself and everything beneath it. ``/team-a``
    therefore allows ``/team-a/db/password`` but not ``/team-admin``: matching is
    done on path segments, never on a naive string prefix.
    """

    job_id: str
    allowed_paths: frozenset[str]
    denied_attempts: list[str] = field(default_factory=list)

    @classmethod
    def from_paths(cls, job_id: str, paths: list[str]) -> JobAccessPolicy:
        return cls(job_id=job_id, allowed_paths=frozenset(paths))

    def allows(self, name: str) -> bool:
        return any(name == allowed or name.startswith(f"{allowed}/") for allowed in self.allowed_paths)

    def authorize(self, name: str) -> None:
        """Guard a single read or a batch request before it reaches the SDK."""
        if self.allows(name):
            return
        self.denied_attempts.append(name)
        raise JobAccessDeniedError(
            f"job {self.job_id!r} is not allowed to read {name!r}; registered paths: {sorted(self.allowed_paths)}",
        )

    def filter_visible(self, requested_path: str, keys: list[str]) -> list[str]:
        """Drop keys the service returned that the job must not see.

        Providers strip the requested path from returned keys (e.g. SSM returns
        ``db/password`` for a request on ``/team-a``), so relative keys are
        re-qualified against the requested path before the allow-list is applied.
        Keys already given as full names are checked as-is.
        """
        visible: list[str] = []
        for key in keys:
            # Providers reduce returned names to the part after the requested
            # path (e.g. SSM returns "db/password" for "/team-a"). Re-qualify
            # relative keys to their full name before applying the allow-list;
            # names that already look like full paths are checked as-is.
            full_name = key if key.startswith("/") else f"{requested_path.rstrip('/')}/{key.lstrip('/')}"
            if self.allows(full_name):
                visible.append(key)
        return visible
