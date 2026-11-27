"""Artifact approval checks shared by the requirements and pylock install paths."""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal
from urllib.parse import unquote, urlsplit

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

from tox.tox_env.errors import Fail

if TYPE_CHECKING:
    from collections.abc import Sequence

    from tox.tox_env.python.pip.req.file import ParsedRequirement
    from tox.tox_env.python.pip.req_file import PythonConstraints, PythonDeps
    from tox.tox_env.python.pylock import Pylock

ApprovalStatus = Literal["approved", "revoked", "denied", "unavailable"]

_POLICY_FILENAMES: Final[tuple[str, ...]] = ("approvals.json", "approvals.toml", "artifact-approvals.json")


class ApprovalError(Fail):
    """Raised when one or more installation artifacts do not have current approval."""


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """A concrete installable artifact and the source tox will obtain it from."""

    name: str
    version: str | None
    source: str
    sha256: str | None = None
    filename: str | None = None
    kind: str = "wheel"
    issues: tuple[str, ...] = ()

    @property
    def canonical_name(self) -> str:
        """:returns: the normalized distribution name."""
        return canonicalize_name(self.name)

    @property
    def identity(self) -> str:
        """Stable identity preferring the content digest and retaining the source."""
        digest = f"sha256:{self.sha256}" if self.sha256 else "sha256:unavailable"
        version = self.version or "unversioned"
        return f"{self.canonical_name}@{version}+{digest}?source={self.source}"

    def as_dict(self) -> dict[str, Any]:
        """:returns: a JSON-able representation used in evidence and cache keys."""
        return {
            "name": self.name,
            "canonical_name": self.canonical_name,
            "version": self.version,
            "source": self.source,
            "sha256": self.sha256,
            "filename": self.filename,
            "kind": self.kind,
            "issues": list(self.issues),
            "identity": self.identity,
        }


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """The current policy decision for one artifact."""

    artifact: ArtifactRef
    status: ApprovalStatus
    reason: str
    approval_id: str | None = None

    @property
    def allowed(self) -> bool:
        """:returns: whether the artifact may be installed."""
        return self.status == "approved" and not self.artifact.issues

    def as_dict(self) -> dict[str, Any]:
        """:returns: a JSON-able decision."""
        return {
            "status": self.status,
            "allowed": self.allowed,
            "reason": self.reason,
            "approval_id": self.approval_id,
            "artifact": self.artifact.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class ApprovalEvidence:
    """The same approval result produced before resolution and presented to installation."""

    decisions: tuple[ApprovalDecision, ...]
    policy_path: Path | None = None
    enabled: bool = True
    context: str = "dependencies"
    digest: str = ""

    @property
    def approved(self) -> bool:
        """:returns: whether every reviewed artifact is currently approved."""
        return self.enabled and all(decision.allowed for decision in self.decisions)

    @property
    def artifacts(self) -> tuple[ArtifactRef, ...]:
        """:returns: reviewed artifacts."""
        return tuple(decision.artifact for decision in self.decisions)

    def as_dict(self) -> dict[str, Any]:
        """:returns: canonical evidence data."""
        return {
            "schema_version": 1,
            "enabled": self.enabled,
            "approved": self.approved,
            "context": self.context,
            "policy_path": str(self.policy_path) if self.policy_path is not None else None,
            "digest": self.digest,
            "artifacts": [artifact.as_dict() for artifact in self.artifacts],
            "decisions": [decision.as_dict() for decision in self.decisions],
        }

    def cache_value(self) -> dict[str, Any]:
        """:returns: stable per-artifact data for tox's install cache."""
        return {
            "artifacts": [
                {
                    "identity": decision.artifact.identity,
                    "status": decision.status,
                    "approval_id": decision.approval_id,
                }
                for decision in self.decisions
            ],
        }


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    """Parsed artifact approval policy."""

    path: Path
    entries: tuple[dict[str, Any], ...] = field(default=())
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> ApprovalPolicy:
        """Load a JSON or TOML policy.

        :param path: policy file path
        :returns: parsed policy
        :raises ApprovalError: when the policy cannot be read or parsed
        """
        try:
            text = path.read_text(encoding="utf-8-sig")
            data = tomllib.loads(text) if path.suffix.lower() == ".toml" else json.loads(text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            msg = f"cannot load artifact approval policy {path}: {exc}"
            raise ApprovalError(msg) from exc
        if not isinstance(data, dict):
            msg = f"artifact approval policy {path} must contain a table/object"
            raise ApprovalError(msg)
        entries = _policy_entries(data)
        return cls(path=path, entries=tuple(entries), raw=data)

    def review(self, artifacts: Sequence[ArtifactRef], context: str) -> ApprovalEvidence:
        """Review artifacts against the current policy file.

        :param artifacts: concrete artifacts selected for installation
        :param context: install section/type for diagnostics
        :returns: evidence for all artifacts
        """
        decisions = tuple(_review_one(artifact, self) for artifact in artifacts)
        body = {
            "policy": _canonical_policy(self.raw),
            "context": context,
            "artifacts": [artifact.as_dict() for artifact in artifacts],
        }
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return ApprovalEvidence(decisions=decisions, policy_path=self.path, context=context, digest=digest)


class ApprovalGate:
    """Locate the current policy and enforce it for one installation request."""

    def __init__(self, configured_path: str | Path | None = None, root: Path | None = None) -> None:
        self.root = (root or Path.cwd()).resolve()
        self.path = self._resolve_policy_path(configured_path)

    def _resolve_policy_path(self, configured_path: str | Path | None) -> Path | None:
        env_path = (
            os.environ.get("TOX_ARTIFACT_APPROVALS")
            or os.environ.get("TOX_APPROVALS_FILE")
            or os.environ.get("TOX_APPROVAL_POLICY")
        )
        value = configured_path if configured_path not in (None, "") else env_path
        if value:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = self.root / path
            path = path.resolve()
            if not path.is_file():
                msg = f"artifact approval policy not found: {path}"
                raise ApprovalError(msg)
            return path
        for name in _POLICY_FILENAMES:
            candidate = self.root / name
            if candidate.is_file():
                return candidate.resolve()
        return None

    @property
    def enabled(self) -> bool:
        """:returns: whether an approval policy is present."""
        return self.path is not None

    def review(
        self,
        artifacts: Sequence[ArtifactRef],
        context: str = "dependencies",
        *,
        raise_on_deny: bool = True,
    ) -> ApprovalEvidence:
        """Review artifacts and optionally raise on the first blocked artifact.

        :param artifacts: artifacts selected for installation
        :param context: install context
        :param raise_on_deny: raise when the evidence is not fully approved
        :returns: approval evidence
        :raises ApprovalError: when enforcement is requested and approval fails
        """
        if self.path is None:
            return ApprovalEvidence(decisions=(), enabled=False, context=context)
        evidence = ApprovalPolicy.load(self.path).review(artifacts, context)
        if raise_on_deny and not evidence.approved:
            raise ApprovalError(render_evidence_failure(evidence))
        return evidence


def render_evidence_failure(evidence: ApprovalEvidence) -> str:
    """Render a actionable, non-secret approval failure.

    :param evidence: failed evidence
    :returns: error message
    """
    lines = [f"dependency artifact approval failed for {evidence.context}:"]
    for decision in evidence.decisions:
        if not decision.allowed:
            artifact = decision.artifact
            lines.append(f"  - [{decision.status}] {artifact.identity}: {decision.reason}")
    lines.append(f"current policy: {evidence.policy_path}")
    return "\n".join(lines)


def artifact_from_local_wheel(
    path: str | Path,
    *,
    base: Path | None = None,
    hashes: Mapping[str, str] | Sequence[str] | None = None,
    source: str | None = None,
    name: str | None = None,
    version: str | None = None,
) -> ArtifactRef:
    """Create an artifact reference from a local wheel, computing its SHA-256.

    :param path: wheel path, absolute or relative to ``base``
    :param base: base directory for relative paths
    :param hashes: hashes declared by the requirement or lock file
    :param source: explicit source (used when source differs from the local path)
    :param name: fallback distribution name
    :param version: fallback distribution version
    :returns: concrete artifact identity
    """
    wheel_path = Path(path)
    if not wheel_path.is_absolute() and base is not None:
        wheel_path = Path(base) / wheel_path
    with suppress(OSError):
        wheel_path = wheel_path.resolve()
    wheel_name = name
    wheel_version = version
    filename = wheel_path.name
    parsed_name: Any = None
    parsed_version: Any = None
    with suppress(Exception):
        parsed_name, parsed_version, _, _ = parse_wheel_filename(filename)
    if parsed_name is not None:
        wheel_name = str(parsed_name)
    if parsed_version is not None:
        wheel_version = str(parsed_version)

    issues: list[str] = []
    sha256 = None
    if wheel_path.is_file():
        sha256 = _sha256_file(wheel_path)
    declared = _normalize_hashes(hashes)
    declared_sha256 = declared.get("sha256")
    if declared_sha256:
        if sha256 is None:
            sha256 = declared_sha256
        elif declared_sha256.lower() != sha256.lower():
            issues.append(f"sha256 mismatch: declared {declared_sha256}, actual {sha256}")
    elif not wheel_path.is_file():
        issues.append("local artifact does not exist and no sha256 was declared")
    if not wheel_name:
        wheel_name = wheel_path.stem.split("-")[0]
    return ArtifactRef(
        name=wheel_name,
        version=wheel_version,
        source=source or str(wheel_path),
        sha256=sha256,
        filename=filename,
        issues=tuple(issues),
    )


def artifacts_from_python_deps(
    deps: PythonDeps,
    constraints: PythonConstraints | None = None,
    marker_environment: Mapping[str, Any] | None = None,
) -> list[ArtifactRef]:
    """Extract concrete local/direct artifacts selected by expanded requirements.

    Constraint specifiers and markers are applied so inactive or impossible entries do not become evidence.

    :param deps: expanded tox requirements object
    :param constraints: optional constraint set
    :param marker_environment: target marker environment
    :returns: artifact references and unresolved-requirement placeholders
    """
    from packaging.markers import default_environment

    marker_env = dict(marker_environment or default_environment())
    constraint_specs = _constraint_specifiers(constraints, marker_env)
    result: list[ArtifactRef] = []
    find_links = _find_link_dirs(deps)

    for parsed in deps.requirements:
        if parsed.options.get("is_constraint"):
            continue
        requirement = parsed.requirement
        marker = getattr(requirement, "marker", None)
        if marker is not None and not marker.evaluate(marker_env):
            continue

        direct = _direct_wheel_artifact(parsed)
        if direct is not None:
            if constraint_specs and isinstance(requirement, Requirement):
                for spec in constraint_specs.get(canonicalize_name(requirement.name), ()):
                    if direct.version and spec.version and not spec.contains(direct.version, prereleases=True):
                        direct = replace(
                            direct,
                            issues=(*direct.issues, f"constraint {spec} excludes version"),
                        )
            result.append(direct)
            continue

        if isinstance(requirement, Requirement) and requirement.url:
            result.append(_url_artifact(requirement.name, None, requirement.url, parsed.options.get("hash")))
            continue

        selected = _select_local_find_link(requirement, find_links, constraint_specs)
        if selected is not None:
            result.append(selected)
        else:
            name = getattr(requirement, "name", str(requirement))
            version = _single_version(requirement)
            result.append(
                ArtifactRef(
                    name=name,
                    version=version,
                    source="unresolved:index-or-other-remote-source",
                    issues=("approval needs a direct URL/path, hashes, or a local --find-links wheel",),
                )
            )
    return result


def artifacts_from_pylock(pylock: Pylock) -> list[ArtifactRef]:
    """Extract the local/locked source artifacts selected by a Pylock file.

    :param pylock: parsed tox pylock object
    :returns: selected artifact references
    """
    selected = pylock.selected_artifacts()
    result: list[ArtifactRef] = []
    for item in selected:
        hashes = dict(item.hashes)
        location = item.location
        path = _location_to_path(location, pylock.path.parent)
        if path is not None and path.suffix.lower() == ".whl":
            result.append(
                artifact_from_local_wheel(
                    path,
                    hashes=hashes,
                    name=item.name,
                    version=item.version,
                )
            )
        else:
            sha256 = hashes.get("sha256")
            result.append(
                ArtifactRef(
                    name=item.name,
                    version=item.version,
                    source=location,
                    sha256=sha256,
                    filename=Path(urlsplit(location).path).name or None,
                    kind=path.suffix.lstrip(".") if path is not None and path.suffix else "source",
                    issues=() if sha256 or location.startswith("file:") or Path(location).exists() else ("no sha256",),
                )
            )
    return result


def _review_one(artifact: ArtifactRef, policy: ApprovalPolicy) -> ApprovalDecision:
    matches = [entry for entry in policy.entries if _entry_matches(entry, artifact, policy.path.parent)]
    revoked = [entry for entry in matches if _entry_status(entry) == "revoked"]
    if revoked:
        entry = revoked[0]
        return ApprovalDecision(
            artifact=artifact,
            status="revoked",
            reason=str(entry.get("reason") or entry.get("revocation_reason") or "approval has been revoked"),
            approval_id=_entry_id(entry),
        )
    approved = [entry for entry in matches if _entry_status(entry) == "approved"]
    if artifact.issues:
        return ApprovalDecision(
            artifact=artifact,
            status="denied",
            reason="; ".join(artifact.issues),
            approval_id=_entry_id(approved[0]) if approved else None,
        )
    if approved:
        return ApprovalDecision(
            artifact=artifact,
            status="approved",
            reason=str(approved[0].get("reason") or "current approval policy allows this exact artifact"),
            approval_id=_entry_id(approved[0]),
        )
    partial = [entry for entry in policy.entries if _same_name_version(entry, artifact)]
    if partial:
        return ApprovalDecision(
            artifact=artifact,
            status="denied",
            reason="name/version matches but source or digest is not approved",
        )
    return ApprovalDecision(artifact=artifact, status="denied", reason="no current artifact approval")


def _entry_matches(entry: dict[str, Any], artifact: ArtifactRef, base: Path) -> bool:
    if not _same_name_version(entry, artifact):
        return False
    entry_sha = _entry_sha256(entry)
    source_match = _entry_source_matches(entry, artifact, base)
    if entry_sha and artifact.sha256:
        if entry_sha.lower() != artifact.sha256.lower():
            return False
        # A digest is sufficient unless the policy also pins a source.
        return source_match if _entry_has_source(entry) else True
    if entry_sha and not artifact.sha256:
        return False
    if _entry_has_source(entry):
        return source_match
    # A name/version-only entry is intentionally not an artifact approval.
    return bool(entry.get("allow_any_artifact") or entry.get("artifact_match") == "name-version")


def _same_name_version(entry: dict[str, Any], artifact: ArtifactRef) -> bool:
    entry_name = entry.get("name") or entry.get("package") or entry.get("package_name")
    if entry_name and canonicalize_name(str(entry_name)) != artifact.canonical_name:
        return False
    entry_version = entry.get("version")
    return entry_version in (None, "*") or artifact.version is None or str(entry_version) == artifact.version


def _entry_has_source(entry: dict[str, Any]) -> bool:
    return any(entry.get(key) for key in ("path", "file", "wheel", "source", "location", "url", "uri"))


def _entry_source_matches(entry: dict[str, Any], artifact: ArtifactRef, base: Path) -> bool:
    values = [entry.get(key) for key in ("path", "file", "wheel", "source", "location", "url", "uri")]
    for value in values:
        if not value:
            continue
        expected_source = _canonical_policy_source(str(value), base)
        actual_source = _canonical_artifact_source(artifact.source)
        if expected_source == actual_source:
            return True
        if expected_source.startswith("file:") and expected_source == Path(actual_source).resolve().as_uri():
            return True
    return False


def _canonical_artifact_source(source: str) -> str:
    if source.startswith("file:"):
        return _uri_to_path(source)
    if "://" in source:
        parts = urlsplit(source)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        return f"{parts.scheme.lower()}://{netloc}{parts.path}"
    try:
        return str(Path(source).expanduser().resolve())
    except OSError:
        return source


def _canonical_policy_source(value: str, base: Path) -> str:
    if value.startswith("file:"):
        return _uri_to_path(value)
    if "://" in value:
        return _canonical_artifact_source(value)
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _uri_to_path(uri: str) -> str:
    parsed = urlsplit(uri)
    path = unquote(parsed.path)
    if os.name == "nt" and path.startswith("/"):
        path = path[1:]
    return str(Path(path).resolve())


def _entry_sha256(entry: dict[str, Any]) -> str | None:
    if entry.get("sha256"):
        return str(entry["sha256"])
    hashes = entry.get("hashes")
    if isinstance(hashes, dict) and hashes.get("sha256"):
        return str(hashes["sha256"])
    for value in entry.get("digests", ()) if isinstance(entry.get("digests"), (list, tuple)) else ():
        if str(value).startswith("sha256:"):
            return str(value).split(":", 1)[1]
    return None


def _entry_status(entry: dict[str, Any]) -> ApprovalStatus:
    status = str(entry.get("status", "")).lower()
    if status in {"revoked", "revoke", "withdrawn"} or entry.get("revoked") is True:
        return "revoked"
    if status in {"denied", "deny", "blocked", "forbidden"} or entry.get("approved") is False or entry.get("allow") is False:
        return "denied"
    if status in {"approved", "approve", "allowed", "allow"} or entry.get("approved") is True or entry.get("allow") is True:
        return "approved"
    return "approved" if _entry_has_identity(entry) else "denied"


def _entry_has_identity(entry: dict[str, Any]) -> bool:
    return _entry_sha256(entry) is not None or _entry_has_source(entry)


def _entry_id(entry: dict[str, Any]) -> str | None:
    value = entry.get("id") or entry.get("approval_id") or entry.get("ticket")
    return str(value) if value else None


def _policy_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    status_by_key = {"revoked": "revoked", "deny": "denied", "allow": "approved", "allowlist": "approved"}
    for key in ("approvals", "approved_artifacts", "artifacts", "allowlist", "allow", "revoked", "deny"):
        if key not in data:
            continue
        result.extend(_coerce_policy_entries(data[key], status_by_key.get(key, "approved")))
    if result:
        return result
    for key, value in data.items():
        if isinstance(value, dict) and key not in {"options", "metadata"}:
            item = dict(value)
            item.setdefault("id", key)
            result.append(item)
    return result


def _coerce_policy_entries(value: Any, status: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            if isinstance(item, dict):
                entry = dict(item)
                entry.setdefault("id", key)
                entry.setdefault("status", status)
                result.append(entry)
            elif isinstance(item, str):
                entry = _entry_from_string(item, status)
                entry.setdefault("id", key)
                result.append(entry)
        return result
    if isinstance(value, list):
        return [item if isinstance(item, dict) else _entry_from_string(str(item), status) for item in value]
    if isinstance(value, str):
        return [_entry_from_string(value, status)]
    return []


def _entry_from_string(value: str, status: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"status": status}
    text = value.strip()
    source: str | None = None
    if "?source=" in text:
        identity, source = text.split("?source=", 1)
        entry["source"] = source
        text = identity
    if "+sha256:" in text:
        name_version, digest = text.split("+sha256:", 1)
        entry["sha256"] = digest
        if "@" in name_version:
            name, version = name_version.rsplit("@", 1)
            entry["name"] = name
            entry["version"] = version
        return entry
    if text.startswith("sha256:"):
        entry["sha256"] = text.split(":", 1)[1]
        return entry
    if len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text):
        entry["sha256"] = text
        return entry
    if "/" in text or text.endswith(".whl"):
        entry["path"] = text
        return entry
    entry["id"] = text
    return entry


def _canonical_policy(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical_policy(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_canonical_policy(item) for item in value]
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handler:
        for chunk in iter(lambda: handler.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_hashes(hashes: Mapping[str, str] | Sequence[str] | None) -> dict[str, str]:
    if not hashes:
        return {}
    if isinstance(hashes, Mapping):
        return {str(key).lower(): str(value) for key, value in hashes.items()}
    result: dict[str, str] = {}
    for value in hashes:
        text = str(value)
        if ":" in text:
            algorithm, digest = text.split(":", 1)
            result[algorithm.lower()] = digest
        elif "=" in text:
            algorithm, digest = text.split("=", 1)
            result[algorithm.lower()] = digest
    return result


def _direct_wheel_artifact(parsed: ParsedRequirement) -> ArtifactRef | None:
    raw = str(parsed.requirement)
    requirement = parsed.requirement
    url = getattr(requirement, "url", None)
    if url and urlsplit(url).path.lower().endswith(".whl"):
        path = _location_to_path(url, Path(parsed.from_file).parent)
        return artifact_from_local_wheel(
            path or Path(urlsplit(url).path),
            base=Path(parsed.from_file).parent if path is None else None,
            hashes=parsed.options.get("hash"),
            source=url,
            name=getattr(requirement, "name", None),
            version=_single_version(requirement),
        )
    path_text = raw.split("#", 1)[0]
    bracket = path_text.find("[")
    if bracket >= 0:
        path_text = path_text[:bracket]
    if path_text.lower().endswith(".whl"):
        return artifact_from_local_wheel(
            path_text,
            base=Path(parsed.from_file).parent,
            hashes=parsed.options.get("hash"),
        )
    return None


def _url_artifact(name: str, version: str | None, url: str, hashes: Any) -> ArtifactRef:
    normalized = _normalize_hashes(hashes if isinstance(hashes, (list, tuple, dict)) else None)
    return ArtifactRef(
        name=name,
        version=version,
        source=url,
        sha256=normalized.get("sha256"),
        filename=Path(urlsplit(url).path).name or None,
        kind=Path(urlsplit(url).path).suffix.lstrip(".") or "url",
    )


def _location_to_path(location: str, base: Path) -> Path | None:
    if location.startswith("file:"):
        return Path(_uri_to_path(location))
    if "://" in location:
        return None
    path = Path(location)
    return path if path.is_absolute() else (base / path).resolve()


def _single_version(requirement: Any) -> str | None:
    specifier = getattr(requirement, "specifier", None)
    if specifier is None:
        return None
    versions = [spec.version for spec in specifier if spec.operator in {"==", "==="} and spec.version]
    return versions[0] if len(versions) == 1 else None


def _constraint_specifiers(
    constraints: PythonConstraints | None,
    marker_env: Mapping[str, Any],
) -> dict[str, list[Any]]:
    if constraints is None:
        return {}
    result: dict[str, list[Any]] = {}
    for parsed in constraints.requirements:
        requirement = parsed.requirement
        if not isinstance(requirement, Requirement):
            continue
        marker = requirement.marker
        if marker is not None and not marker.evaluate(dict(marker_env)):
            continue
        result.setdefault(canonicalize_name(requirement.name), []).extend(list(requirement.specifier))
    return result


def _find_link_dirs(deps: PythonDeps) -> list[Path]:
    try:
        values = getattr(deps.options, "find_links", []) or []
    except Exception:  # noqa: BLE001 - malformed requirement input is handled by tox's normal installer path
        return []
    result = []
    for value in values:
        path = Path(str(value))
        if not path.is_absolute():
            path = deps.path.parent / path
        result.append(path)
    return result


def _select_local_find_link(
    requirement: Any,
    find_links: Sequence[Path],
    constraint_specs: Mapping[str, Sequence[Any]],
) -> ArtifactRef | None:
    if not hasattr(requirement, "name") or not find_links:
        return None
    candidates: list[tuple[Any, Path]] = []
    constraint_list = list(constraint_specs.get(canonicalize_name(requirement.name), ()))
    for directory in find_links:
        if not directory.is_dir():
            continue
        for wheel in sorted(directory.glob("*.whl")):
            try:
                name, version, _, _ = parse_wheel_filename(wheel.name)
            except Exception:  # noqa: BLE001 - ignore unrelated/invalid wheels
                continue
            if canonicalize_name(str(name)) != canonicalize_name(requirement.name):
                continue
            if requirement.specifier and not requirement.specifier.contains(str(version), prereleases=True):
                continue
            if any(not spec.contains(str(version), prereleases=True) for spec in constraint_list):
                continue
            candidates.append((version, wheel))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return artifact_from_local_wheel(candidates[0][1])


__all__ = [
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalEvidence",
    "ApprovalGate",
    "ApprovalPolicy",
    "ArtifactRef",
    "artifacts_from_pylock",
    "artifacts_from_python_deps",
    "artifact_from_local_wheel",
    "render_evidence_failure",
]
