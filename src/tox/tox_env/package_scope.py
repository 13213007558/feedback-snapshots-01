"""Scope contract for reuse of shared package build environments and artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Iterable, Literal, Mapping

from tox.tox_env.errors import Fail

ReuseStatus = Literal["reused", "build_required", "denied"]


def freeze_scope_value(value: Any) -> Any:
    """Convert a scope value into a stable, JSON-serializable structure."""
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), freeze_scope_value(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(freeze_scope_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((repr(freeze_scope_value(item)), freeze_scope_value(item)) for item in value))
    if isinstance(value, Path):
        return str(value)
    return value


def scope_fingerprint(value: Any) -> str:
    """Return a stable fingerprint for a scope-relevant value."""
    frozen = freeze_scope_value(value)
    payload = json.dumps(frozen, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


class PackageScopeError(Fail):
    """Base class for package scope contract failures."""


class BuildCapabilityDenied(PackageScopeError):
    """A build used a capability outside its approved scope."""

    def __init__(self, package_name: str, scope_key: str, denied: Iterable[str]) -> None:
        self.package_name: Final[str] = package_name
        self.scope_key: Final[str] = scope_key
        self.denied: Final[frozenset[str]] = frozenset(denied)
        capabilities = ", ".join(sorted(self.denied)) or "<unknown>"
        super().__init__(
            f"package build {package_name!r} used capabilities {capabilities} not approved by scope {scope_key[:12]}"
        )


class PackageReuseDenied(PackageScopeError):
    """A cached package cannot serve a scope because its build exceeded that scope."""

    def __init__(self, decision: ReuseDecision) -> None:
        self.decision: Final[ReuseDecision] = decision
        denied = ", ".join(sorted(decision.out_of_scope)) or "incompatible build factors"
        super().__init__(
            f"refusing to reuse package {decision.package_name!r} for scope {decision.requested_key[:12]}: {denied}"
        )


@dataclass(frozen=True, slots=True)
class PackageBuildScope:
    """Approved capabilities and exact factors that characterize a package request."""

    approved: frozenset[str] = field(default_factory=frozenset)
    factors: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def create(
        cls,
        approved: Iterable[str] = (),
        factors: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    ) -> PackageBuildScope:
        """Create a scope from capability names and scope-relevant factors."""
        approved_set = frozenset(str(item) for item in approved)
        if factors is None:
            factor_items: tuple[tuple[str, Any], ...] = ()
        elif isinstance(factors, Mapping):
            factor_items = tuple(sorted((str(key), freeze_scope_value(value)) for key, value in factors.items()))
        else:
            factor_items = tuple(sorted((str(key), freeze_scope_value(value)) for key, value in factors))
        return cls(approved=approved_set, factors=factor_items)

    @property
    def fingerprint(self) -> str:
        """Stable identity for the complete approval and factor scope."""
        return scope_fingerprint({"approved": sorted(self.approved), "factors": self.factors})

    def permits(self, capabilities: Iterable[str]) -> bool:
        """Check whether every supplied capability is approved."""
        return frozenset(capabilities) <= self.approved


@dataclass(frozen=True, slots=True)
class ScopedArtifact:
    """A built artifact together with the scope evidence needed to judge reuse."""

    package_name: str
    scope_key: str
    path: Path
    digest: str | None
    used: frozenset[str] = field(default_factory=frozenset)
    factors: tuple[tuple[str, Any], ...] = ()
    builder: str | None = None
    plugins: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()

    def serves(self, requested: PackageBuildScope) -> bool:
        """Whether this artifact's actual build evidence fits the requested scope."""
        return self.factors == requested.factors and requested.permits(self.used)


@dataclass(frozen=True, slots=True)
class ReuseDecision:
    """The result of checking whether an existing artifact may be reused."""

    status: ReuseStatus
    package_name: str
    requested_key: str
    artifact: ScopedArtifact | None = None
    reason: str = ""
    out_of_scope: frozenset[str] = field(default_factory=frozenset)
    factor_conflicts: tuple[str, ...] = ()

    @property
    def reused(self) -> bool:
        """Whether the decision permits reusing an artifact."""
        return self.status == "reused" and self.artifact is not None


@dataclass(slots=True)
class PackagePreparation:
    """A named preparation under one approved build scope."""

    name: str
    scope: PackageBuildScope
    artifacts: list[ScopedArtifact] = field(default_factory=list)
    prepare_count: int = 0

    @property
    def key(self) -> tuple[str, str]:
        """Registry key for this named preparation."""
        return self.name, self.scope.fingerprint

    @property
    def latest(self) -> ScopedArtifact | None:
        """The most recently recorded artifact for this preparation."""
        return self.artifacts[-1] if self.artifacts else None


@dataclass(frozen=True, slots=True)
class PackageConsumption:
    """The concrete package view that enters one test run."""

    env_name: str
    path: Path
    digest: str | None = None
    source: ScopedArtifact | None = None


@dataclass(frozen=True, slots=True)
class PackageRunRecord:
    """Record connecting a test run environment to its reuse decision and artifact."""

    env_name: str
    preparation: PackagePreparation
    decision: ReuseDecision
    consumed: PackageConsumption | None = None

    @property
    def artifact(self) -> ScopedArtifact | None:
        """The artifact authorized by the decision, if any."""
        return self.decision.artifact

    @property
    def consumed_path(self) -> Path | None:
        """The package path actually consumed by the run environment."""
        return None if self.consumed is None else self.consumed.path

    @property
    def reused(self) -> bool:
        """Whether the run reused an existing artifact."""
        return self.decision.reused


class PackageReuseContract:
    """Registry that prevents package environments from being reused by name alone."""

    def __init__(self) -> None:
        self.preparations: dict[tuple[str, str], PackagePreparation] = {}
        self.runs: list[PackageRunRecord] = []

    @property
    def conflicts(self) -> tuple[PackageRunRecord, ...]:
        """Run records where reuse was refused because the scope was incompatible."""
        return tuple(run for run in self.runs if run.decision.status == "denied")

    def report(self) -> dict[str, Any]:
        """Return a JSON-serializable summary of preparations, runs, and conflicts."""
        return {
            "preparations": [
                {"name": prep.name, "scope": prep.scope.fingerprint, "builds": len(prep.artifacts)}
                for prep in self.preparations.values()
            ],
            "runs": [
                {
                    "env": run.env_name,
                    "package": run.decision.package_name,
                    "scope": run.decision.requested_key,
                    "status": run.decision.status,
                    "reason": run.decision.reason,
                    "consumed": None if run.consumed_path is None else str(run.consumed_path),
                    "out_of_scope": sorted(run.decision.out_of_scope),
                    "factor_conflicts": list(run.decision.factor_conflicts),
                }
                for run in self.runs
            ],
            "conflicts": [run.env_name for run in self.conflicts],
        }

    def prepare(
        self,
        name: str,
        scope: PackageBuildScope | None = None,
        *,
        approved: Iterable[str] = (),
        factors: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    ) -> PackagePreparation:
        """Record or fetch the preparation for a named package and scope."""
        resolved_scope = scope or PackageBuildScope.create(approved=approved, factors=factors)
        key = (name, resolved_scope.fingerprint)
        preparation = self.preparations.get(key)
        if preparation is None:
            preparation = PackagePreparation(name=name, scope=resolved_scope)
            self.preparations[key] = preparation
        preparation.prepare_count += 1
        return preparation

    def authorize_build(self, preparation: PackagePreparation, used: Iterable[str]) -> frozenset[str]:
        """Reject a build before side effects when it requests unapproved capabilities."""
        used_capabilities = frozenset(used)
        denied = used_capabilities - preparation.scope.approved
        if denied:
            raise BuildCapabilityDenied(preparation.name, preparation.scope.fingerprint, denied)
        return used_capabilities

    def record_build(
        self,
        preparation: PackagePreparation,
        path: str | Path,
        *,
        used: Iterable[str] = (),
        calls: Iterable[str] = (),
        builder: str | None = None,
        plugins: Iterable[str] = (),
        digest: str | None = None,
        compute_digest: bool = True,
    ) -> ScopedArtifact:
        """Record an artifact after verifying the build stayed inside its approval."""
        used_capabilities = self.authorize_build(preparation, used)
        artifact_path = Path(path)
        resolved_digest = digest
        if resolved_digest is None and compute_digest and artifact_path.is_file():
            resolved_digest = sha256(artifact_path.read_bytes()).hexdigest()
        artifact = ScopedArtifact(
            package_name=preparation.name,
            scope_key=preparation.scope.fingerprint,
            path=artifact_path,
            digest=resolved_digest,
            used=used_capabilities,
            factors=preparation.scope.factors,
            builder=builder,
            plugins=tuple(sorted(str(item) for item in plugins)),
            calls=tuple(calls),
        )
        preparation.artifacts.append(artifact)
        return artifact

    def artifacts(self, name: str) -> tuple[ScopedArtifact, ...]:
        """Return all recorded artifacts for a package name, oldest first."""
        return tuple(
            artifact
            for preparation in self.preparations.values()
            if preparation.name == name
            for artifact in preparation.artifacts
        )

    def check_reuse(self, name: str, scope: PackageBuildScope) -> ReuseDecision:
        """Check whether an existing artifact is safe to reuse under ``scope``."""
        requested_key = scope.fingerprint
        exact = self.preparations.get((name, requested_key))
        if exact is not None and exact.latest is not None:
            return ReuseDecision(
                status="reused",
                package_name=name,
                requested_key=requested_key,
                artifact=exact.latest,
                reason="matching-name-and-scope",
            )

        denied_capabilities: set[str] = set()
        factor_conflicts: set[str] = set()
        denied = False
        for artifact in reversed(self.artifacts(name)):
            missing = artifact.used - scope.approved
            if artifact.factors != scope.factors:
                denied = True
                artifact_factors = dict(artifact.factors)
                requested_factors = dict(scope.factors)
                for key in artifact_factors.keys() | requested_factors.keys():
                    if artifact_factors.get(key) != requested_factors.get(key):
                        factor_conflicts.add(str(key))
            elif missing:
                denied = True
                denied_capabilities.update(missing)
            else:
                return ReuseDecision(
                    status="reused",
                    package_name=name,
                    requested_key=requested_key,
                    artifact=artifact,
                    reason="build-evidence-within-scope",
                )

        if denied:
            return ReuseDecision(
                status="denied",
                package_name=name,
                requested_key=requested_key,
                reason="existing-build-exceeds-requested-scope",
                out_of_scope=frozenset(denied_capabilities),
                factor_conflicts=tuple(sorted(factor_conflicts)),
            )
        return ReuseDecision(
            status="build_required",
            package_name=name,
            requested_key=requested_key,
            reason="no-recorded-artifact",
        )

    def begin_run(
        self,
        env_name: str,
        name: str,
        scope: PackageBuildScope | None = None,
        *,
        approved: Iterable[str] = (),
        factors: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    ) -> PackageRunRecord:
        """Record a run environment and evaluate reuse without raising on denial."""
        preparation = self.prepare(name, scope, approved=approved, factors=factors)
        decision = self.check_reuse(name, preparation.scope)
        record = PackageRunRecord(env_name=env_name, preparation=preparation, decision=decision)
        self.runs.append(record)
        return record

    def record_consumption(
        self,
        run: PackageRunRecord,
        path: str | Path,
        *,
        digest: str | None = None,
        compute_digest: bool = False,
    ) -> PackageRunRecord:
        """Attach the concrete package view installed for a run to its record."""
        package_path = Path(path)
        resolved_digest = digest
        if resolved_digest is None and compute_digest and package_path.is_file():
            resolved_digest = sha256(package_path.read_bytes()).hexdigest()
        consumption = PackageConsumption(
            env_name=run.env_name,
            path=package_path,
            digest=resolved_digest,
            source=run.decision.artifact or run.preparation.latest,
        )
        updated = replace(run, consumed=consumption)
        index = self.runs.index(run)
        self.runs[index] = updated
        return updated

    def request_reuse(
        self,
        env_name: str,
        name: str,
        scope: PackageBuildScope | None = None,
        *,
        approved: Iterable[str] = (),
        factors: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    ) -> PackageRunRecord:
        """Begin a run and raise :class:`PackageReuseDenied` if reuse is out of scope."""
        record = self.begin_run(env_name, name, scope, approved=approved, factors=factors)
        if record.decision.status == "denied":
            raise PackageReuseDenied(record.decision)
        return record


__all__ = [
    "BuildCapabilityDenied",
    "PackageBuildScope",
    "PackageConsumption",
    "PackagePreparation",
    "PackageReuseContract",
    "PackageReuseDenied",
    "PackageRunRecord",
    "PackageScopeError",
    "ReuseDecision",
    "ScopedArtifact",
    "scope_fingerprint",
]
