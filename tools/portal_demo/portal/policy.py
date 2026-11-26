"""Approval policy derived from the build platform's baseline.

An execution approval binds four things together:

* the exact script content (identified by its sha256 digest, so a new version
  of the same file path is a different approval unit),
* the tox environment selected for execution,
* the PEP 723 dependency summary that was parsed,
* the baseline wheelhouse the platform has vetted.

Previewing a new version at an already approved path stays allowed; only
execution is gated.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import Requirement


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalized(name: str) -> str:
    """PEP 503 normalized distribution name (runs of -/_/. become a single dash)."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, slots=True)
class Baseline:
    """The platform-approved offline baseline."""

    wheelhouse: Path
    wheels: frozenset[str]
    python: str

    @classmethod
    def load(cls, wheelhouse: Path, manifest_path: Path) -> Baseline:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        wheels = frozenset(entry["file"] for entry in manifest["wheels"])
        return cls(wheelhouse=wheelhouse.resolve(), wheels=wheels, python=manifest["python"])

    def allows(self, requirements: list[str]) -> bool:
        """Every dependency must resolve to a wheel present in the baseline."""
        available = {_normalized(filename.split("-", 1)[0]) for filename in self.wheels}
        return all(_normalized(Requirement(raw).name) in available for raw in requirements)


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    approved: bool
    reason: str
    content_digest: str
    environment: str
    requirements: tuple[str, ...] = field(default_factory=tuple)


class ApprovalPolicy:
    """Records and evaluates execution approvals."""

    def __init__(self, baseline: Baseline) -> None:
        self._baseline = baseline
        self._approvals: dict[tuple[str, str], tuple[str, ...]] = {}

    def grant(
        self,
        content_digest: str,
        environment: str,
        requirements: tuple[str, ...],
    ) -> ApprovalDecision:
        """An administrator grants execution for one content + environment pair."""
        if not self._baseline.allows(list(requirements)):
            return ApprovalDecision(
                False,
                "dependency outside the approved platform baseline",
                content_digest,
                environment,
                requirements,
            )
        self._approvals[(content_digest, environment)] = requirements
        return ApprovalDecision(True, "execution approval granted", content_digest, environment, requirements)

    def evaluate(
        self,
        content_digest: str,
        environment: str,
        requirements: tuple[str, ...],
    ) -> ApprovalDecision:
        stored = self._approvals.get((content_digest, environment))
        if stored is None:
            return ApprovalDecision(
                False,
                "no execution approval for this content and environment",
                content_digest,
                environment,
                requirements,
            )
        if stored != requirements:
            return ApprovalDecision(
                False,
                "parsed dependency summary no longer matches the approved content",
                content_digest,
                environment,
                requirements,
            )
        if not self._baseline.allows(list(requirements)):
            return ApprovalDecision(
                False,
                "dependency outside the approved platform baseline",
                content_digest,
                environment,
                requirements,
            )
        return ApprovalDecision(True, "approved content and environment", content_digest, environment, requirements)

    @property
    def baseline(self) -> Baseline:
        return self._baseline
