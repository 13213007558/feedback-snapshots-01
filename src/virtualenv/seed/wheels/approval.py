"""Approved seed-wheel sets and their shared AppData ledger.

The ledger gives an online update and an offline creation the same vocabulary:
an *approval* identifies the policy/mirror that was authorized, while a ready
*set* records the exact wheels that were committed under that approval.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from packaging.utils import canonicalize_name

from virtualenv.app_data import AppDataDiskFolder

from .util import Wheel

if TYPE_CHECKING:
    from collections.abc import Iterator

    from virtualenv.app_data.base import AppData

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

SCHEMA: Final[int] = 1
LEDGER_NAME: Final[str] = "seed-approval-ledger"
RECEIPT_NAME: Final[str] = "seed-approval.json"
APPROVAL_ENV_VARS: Final[tuple[str, ...]] = (
    "VIRTUALENV_SEED_APPROVAL",
    "VIRTUALENV_APPROVAL",
)
APPROVAL_ID_ENV_VARS: Final[tuple[str, ...]] = (
    "VIRTUALENV_SEED_APPROVAL_ID",
    "VIRTUALENV_APPROVAL_ID",
)


class ApprovalError(ValueError):
    """An approval document or approved wheel set is invalid."""


class ApprovalNotFoundError(ApprovalError):
    """No locally visible wheel set satisfies the requested approval."""


class ApprovalIntegrityError(ApprovalError):
    """A cached wheel does not match its approved record."""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_distribution(value: str) -> str:
    return canonicalize_name(value)


@dataclass(frozen=True)
class ApprovedWheel:
    """One wheel contained in an approved set.

    :param distribution: normalized distribution name
    :param filename: wheel file name inside the AppData wheel house
    :param version: PEP 440 version parsed from the wheel file name
    :param sha256: optional expected SHA-256 digest

    """

    distribution: str
    filename: str
    version: str
    sha256: str | None = None

    @classmethod
    def from_path(cls, path: Path | str, *, calculate_sha256: bool = True) -> ApprovedWheel:
        """Build an approved-wheel reference from a local wheel file.

        :param path: wheel path
        :param calculate_sha256: whether to hash the file immediately

        :returns: the wheel reference

        :raises ApprovalError: when the path is not a wheel

        """
        wheel_path = Path(path)
        wheel = Wheel.from_path(wheel_path)
        if wheel is None:
            msg = f"not a wheel file: {wheel_path}"
            raise ApprovalError(msg)
        return cls(
            distribution=_canonical_distribution(wheel.distribution),
            filename=wheel.name,
            version=wheel.version,
            sha256=_sha256(wheel_path) if calculate_sha256 and wheel_path.is_file() else None,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovedWheel:
        """Parse a stored or JSON-approved wheel.

        :param data: serialized wheel

        :returns: the wheel reference

        """
        filename = str(data.get("filename") or data.get("name") or "")
        distribution = str(data.get("distribution") or data.get("project") or "").strip()
        version = str(data.get("version") or "").strip()
        if not filename:
            msg = "approved wheel is missing its filename"
            raise ApprovalError(msg)
        wheel = Wheel.from_path(Path(filename))
        if wheel is not None:
            distribution = distribution or wheel.distribution
            version = version or wheel.version
        if not distribution or not version:
            msg = f"approved wheel {filename!r} is missing distribution or version"
            raise ApprovalError(msg)
        digest = data.get("sha256") or data.get("digest")
        return cls(
            distribution=_canonical_distribution(distribution),
            filename=filename,
            version=version,
            sha256=str(digest) if digest else None,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the wheel reference."""
        return asdict(self)

    def matches_path(self, path: Path) -> bool:
        """Check whether a path has this wheel's file name and digest.

        :param path: candidate wheel path

        :returns: whether it matches

        """
        if path.name != self.filename or not path.is_file():
            return False
        return self.sha256 is None or _sha256(path) == self.sha256


@dataclass(frozen=True)
class Approval:
    """An approved mirror/policy identity and optional wheel constraints.

    :param id: stable approval/revision identifier
    :param index_url: approved PEP 503 index or mirror URL
    :param find_links: approved find-links locations
    :param wheels: optional exact wheel constraints, keyed by normalized name
    :param strict: when true, a committed set may contain only listed wheels

    """

    id: str
    index_url: str | None = None
    find_links: tuple[str, ...] = ()
    wheels: Mapping[str, ApprovedWheel] = field(default_factory=dict)
    strict: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Approval:
        """Parse an approval document.

        :param data: approval mapping

        :returns: the approval

        :raises ApprovalError: when the identifier is missing

        """
        approval_id = data.get("id") or data.get("approval_id") or data.get("approval-id")
        if not approval_id:
            msg = "approval document is missing an id/approval_id"
            raise ApprovalError(msg)
        raw_wheels = data.get("wheels") or data.get("packages") or {}
        wheels: dict[str, ApprovedWheel] = {}
        if isinstance(raw_wheels, Mapping):
            for key, value in raw_wheels.items():
                item = dict(value) if isinstance(value, Mapping) else {"filename": value}
                item.setdefault("distribution", key)
                wheel = ApprovedWheel.from_dict(item)
                wheels[wheel.distribution] = wheel
        elif isinstance(raw_wheels, list):
            for value in raw_wheels:
                wheel = ApprovedWheel.from_dict(value)
                wheels[wheel.distribution] = wheel
        find_links = data.get("find_links") or data.get("find-links") or ()
        if isinstance(find_links, str):
            find_links = (find_links,)
        return cls(
            id=str(approval_id),
            index_url=data.get("index_url") or data.get("index-url") or data.get("mirror") or data.get("source"),
            find_links=tuple(str(item) for item in find_links),
            wheels=wheels,
            strict=bool(data.get("strict", False)),
        )

    @classmethod
    def load(
        cls,
        value: str | Mapping[str, Any] | Approval | Path | None = None,
        *,
        env: Mapping[str, str] | None = None,
    ) -> Approval | None:
        """Load an approval from an object, JSON/path text, or environment.

        :param value: approval ID, JSON document, or path to a JSON document
        :param env: environment used when ``value`` is absent

        :returns: the approval, or ``None`` when no approval configuration exists

        """
        if isinstance(value, Approval):
            return value
        if isinstance(value, Mapping):
            return cls.from_dict(value)
        if isinstance(value, Path):
            return cls._load_path(value)
        if value is None:
            environment = os.environ if env is None else env
            for key in APPROVAL_ENV_VARS:
                if environment.get(key):
                    value = environment[key]
                    break
            if value is None:
                approval_id = next((environment[key] for key in APPROVAL_ID_ENV_VARS if environment.get(key)), None)
                if approval_id is None:
                    return None
                return cls(
                    id=approval_id,
                    index_url=environment.get("PIP_INDEX_URL") or environment.get("VIRTUALENV_SEED_INDEX_URL"),
                )
        text = str(value).strip()
        maybe_path = Path(text).expanduser()
        if maybe_path.is_file():
            return cls._load_path(maybe_path)
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return cls(id=text)
        if not isinstance(parsed, Mapping):
            msg = "approval JSON must be an object"
            raise ApprovalError(msg)
        return cls.from_dict(parsed)

    @staticmethod
    def _load_path(path: Path) -> Approval:
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exception:
            msg = f"could not read approval document {path}: {exception}"
            raise ApprovalError(msg) from exception
        if not isinstance(parsed, Mapping):
            msg = f"approval document {path} must contain a JSON object"
            raise ApprovalError(msg)
        return Approval.from_dict(parsed)

    def environment(self, env: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return an environment configured with this approval's mirror.

        :param env: base environment to copy

        :returns: the extended environment

        """
        result = dict(os.environ if env is None else env)
        if self.index_url:
            result["PIP_INDEX_URL"] = str(self.index_url)
            result["PIP_INDEX"] = str(self.index_url)
        if self.find_links:
            result["PIP_FIND_LINKS"] = " ".join(self.find_links)
        result["VIRTUALENV_SEED_APPROVAL_ID"] = self.id
        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialize the approval identity and constraints."""
        return {
            "id": self.id,
            "index_url": self.index_url,
            "find_links": list(self.find_links),
            "strict": self.strict,
            "wheels": [wheel.to_dict() for wheel in self.wheels.values()],
        }


def load_approval(
    value: str | Mapping[str, Any] | Approval | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Approval | None:
    """Load an approval; thin function-style alias for :meth:`Approval.load`."""
    return Approval.load(value, env=env)


@dataclass
class ApprovalSet:
    """A pending, ready, or failed update for one target Python series."""

    id: str
    approval_id: str
    for_py_version: str
    status: str
    created_at: str
    completed_at: str | None = None
    index_url: str | None = None
    find_links: list[str] = field(default_factory=list)
    wheels: list[ApprovedWheel] = field(default_factory=list)
    error: str | None = None
    pid: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalSet:
        """Parse a ledger set."""
        return cls(
            id=str(data["id"]),
            approval_id=str(data["approval_id"]),
            for_py_version=str(data["for_py_version"]),
            status=str(data.get("status", "pending")),
            created_at=str(data.get("created_at") or _now()),
            completed_at=data.get("completed_at"),
            index_url=data.get("index_url"),
            find_links=list(data.get("find_links") or []),
            wheels=[ApprovedWheel.from_dict(item) for item in data.get("wheels") or []],
            error=data.get("error"),
            pid=data.get("pid"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the ledger set."""
        data = asdict(self)
        data["wheels"] = [wheel.to_dict() for wheel in self.wheels]
        return data

    def wheel_for(self, distribution: str) -> ApprovedWheel | None:
        """Return the approved wheel for a distribution, when present."""
        normalized = _canonical_distribution(distribution)
        return next((wheel for wheel in self.wheels if wheel.distribution == normalized), None)


@dataclass(frozen=True)
class ApprovalSelection:
    """A locally visible ready set selected for an offline creation."""

    set: ApprovalSet
    app_data: AppData

    requested_approval_id: str | None = None
    offline: bool = True
    stale: bool = False
    reason: str | None = None

    @property
    def approval_id(self) -> str:
        """The approval identifier recorded on the selected set."""
        return self.set.approval_id

    @property
    def for_py_version(self) -> str:
        """The target Python ``major.minor`` series."""
        return self.set.for_py_version

    @property
    def wheels(self) -> tuple[ApprovedWheel, ...]:
        """The selected wheel references."""
        return tuple(self.set.wheels)

    def wheel_for(self, distribution: str) -> ApprovedWheel | None:
        """Return the selected wheel reference for a distribution."""
        return self.set.wheel_for(distribution)

    def path_for(self, distribution_or_wheel: str | ApprovedWheel) -> Path | None:
        """Return the cached house path for a selected distribution or wheel."""
        approved = (
            distribution_or_wheel
            if isinstance(distribution_or_wheel, ApprovedWheel)
            else self.wheel_for(distribution_or_wheel)
        )
        if approved is None:
            return None
        path = Path(self.app_data.house) / approved.filename
        return path if path.exists() else None

    def wheel_paths(self) -> dict[str, Path]:
        """Return all existing selected wheel paths keyed by distribution."""
        return {
            wheel.distribution: path
            for wheel in self.wheels
            if (path := self.path_for(wheel)) is not None
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable receipt fragment."""
        return {
            "approval_id": self.approval_id,
            "requested_approval_id": self.requested_approval_id,
            "for_py_version": self.for_py_version,
            "offline": self.offline,
            "stale": self.stale,
            "reason": self.reason,
            "set_id": self.set.id,
            "index_url": self.set.index_url,
            "created_at": self.set.created_at,
            "completed_at": self.set.completed_at,
            "wheels": [wheel.to_dict() for wheel in self.wheels],
        }


class ApprovalLedger:
    """Cross-process ledger of approved wheel sets in shared AppData."""

    def __init__(self, app_data: AppData | str | Path) -> None:
        if isinstance(app_data, (str, Path)):
            app_data = AppDataDiskFolder(str(app_data))
        self.app_data: Final[AppData] = app_data

    @property
    def path(self) -> Path:
        """The JSON ledger path."""
        lock = getattr(self.app_data, "lock", None)
        if lock is None:
            msg = "this AppData implementation does not persist an approval ledger"
            raise ApprovalError(msg)
        return Path(lock.path) / "seed-approval" / "ledger.json"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock = getattr(self.app_data, "lock", None)
        if lock is None:
            yield
            return
        with lock.lock_for_key(LEDGER_NAME):
            yield

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema": SCHEMA, "sets": [], "active": {}}
        except (OSError, json.JSONDecodeError) as exception:
            msg = f"seed approval ledger is unreadable: {self.path}: {exception}"
            raise ApprovalError(msg) from exception
        if not isinstance(data, Mapping) or not isinstance(data.get("sets", []), list):
            msg = f"seed approval ledger has an invalid shape: {self.path}"
            raise ApprovalError(msg)
        return dict(data)

    def _write(self, data: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=".ledger-", suffix=".json", dir=str(self.path.parent)
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, ensure_ascii=False, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def sets(self, for_py_version: str | None = None, *, status: str | None = None) -> list[ApprovalSet]:
        """Return ledger sets, newest first, optionally filtered.

        :param for_py_version: target Python series to retain
        :param status: status to retain

        :returns: matching sets

        """
        with self._locked():
            records = [ApprovalSet.from_dict(item) for item in self._read().get("sets", [])]
        records.reverse()
        return [
            record
            for record in records
            if (for_py_version is None or record.for_py_version == for_py_version)
            and (status is None or record.status == status)
        ]

    def get(self, set_id: str) -> ApprovalSet:
        """Return one set by identifier."""
        with self._locked():
            for item in self._read().get("sets", []):
                if item.get("id") == set_id:
                    return ApprovalSet.from_dict(item)
        msg = f"unknown approved wheel set: {set_id}"
        raise ApprovalNotFoundError(msg)

    def begin(
        self,
        approval: Approval | Mapping[str, Any] | str,
        for_py_version: str,
        *,
        wheels: list[ApprovedWheel | Path | str] | None = None,
    ) -> ApprovalSet:
        """Record that an update under an approval has started/queued.

        The approval is frozen into the record, so later edits to the caller's
        approval document cannot rewrite which approval this attempt used.

        """
        parsed = Approval.load(approval) if not isinstance(approval, Approval) else approval
        if parsed is None:
            msg = "an approval is required to begin an approved update"
            raise ApprovalError(msg)
        record = ApprovalSet(
            id=os.urandom(16).hex(),
            approval_id=parsed.id,
            for_py_version=for_py_version,
            status="pending",
            created_at=_now(),
            index_url=parsed.index_url,
            find_links=list(parsed.find_links),
            wheels=[self._wheel_reference(item) for item in wheels or []],
            pid=os.getpid(),
        )
        with self._locked():
            data = self._read()
            data.setdefault("sets", []).append(record.to_dict())
            self._write(data)
        LOGGER.info("began approved seed update %s under approval %s", record.id, record.approval_id)
        return record

    def commit(
        self,
        set_id: str,
        wheels: list[Path | str | ApprovedWheel],
        approval: Approval | Mapping[str, Any] | str | None = None,
    ) -> ApprovalSet:
        """Verify, publish, and activate the wheels for one update attempt.

        The active pointer changes only after every wheel has been copied and
        verified, so a failed commit leaves the previous ready set usable.

        """
        attempt = self.get(set_id)
        parsed = (
            Approval.load(approval)
            if approval is not None and not isinstance(approval, Approval)
            else approval or Approval(
                id=attempt.approval_id,
                index_url=attempt.index_url,
                find_links=tuple(attempt.find_links),
            )
        )
        if parsed is None:
            msg = "an approval is required to commit an approved update"
            raise ApprovalError(msg)
        approved_wheels = [self._prepare_wheel(parsed, item) for item in wheels]
        if parsed.strict:
            missing = set(parsed.wheels) - {wheel.distribution for wheel in approved_wheels}
            if missing:
                msg = f"approved set is missing constrained wheels: {', '.join(sorted(missing))}"
                raise ApprovalError(msg)
        with self._locked():
            data = self._read()
            record = next((item for item in data["sets"] if item.get("id") == set_id), None)
            if record is None:
                msg = f"unknown approved wheel set: {set_id}"
                raise ApprovalNotFoundError(msg)
            record.update({
                "status": "ready",
                "completed_at": _now(),
                "error": None,
                "wheels": [wheel.to_dict() for wheel in approved_wheels],
            })
            data.setdefault("active", {})[attempt.for_py_version] = set_id
            self._write(data)
        return self.get(set_id)

    def record_update(
        self,
        approval: Approval | Mapping[str, Any] | str,
        for_py_version: str,
        wheels: list[Path | str | ApprovedWheel],
    ) -> ApprovalSet:
        """Begin and successfully commit an approved wheel set."""
        parsed = Approval.load(approval) if not isinstance(approval, Approval) else approval
        if parsed is None:
            msg = "an approval is required to record an approved update"
            raise ApprovalError(msg)
        pending = self.begin(parsed, for_py_version)
        return self.commit(pending.id, wheels, parsed)

    @contextmanager
    def attempt(
        self,
        approval: Approval | Mapping[str, Any] | str,
        for_py_version: str,
    ) -> Iterator[ApprovalSet]:
        """Begin an update and mark it failed if the block raises.

        The block must call :meth:`commit` after its wheels are ready; without
        that call the set remains pending and is never selected as active.

        """
        pending = self.begin(approval, for_py_version)
        try:
            yield pending
        except BaseException as exception:
            self.fail(pending.id, exception)
            raise

    def fail(self, set_id: str, error: BaseException | str) -> ApprovalSet:
        """Mark an update failed without changing the active ready set."""
        message = f"{type(error).__name__}: {error}" if isinstance(error, BaseException) else str(error)
        with self._locked():
            data = self._read()
            record = next((item for item in data["sets"] if item.get("id") == set_id), None)
            if record is None:
                msg = f"unknown approved wheel set: {set_id}"
                raise ApprovalNotFoundError(msg)
            record["status"] = "failed"
            record["completed_at"] = _now()
            record["error"] = message
            self._write(data)
        LOGGER.warning("approved seed update %s failed: %s", set_id, message)
        return self.get(set_id)

    def record_failed_update(
        self,
        approval: Approval | Mapping[str, Any] | str,
        for_py_version: str,
        error: BaseException | str,
    ) -> ApprovalSet:
        """Begin and immediately fail an update, useful in recovery probes."""
        pending = self.begin(approval, for_py_version)
        return self.fail(pending.id, error)

    def latest_ready(self, for_py_version: str) -> ApprovalSet | None:
        """Return the active ready set, falling back to the newest ready set."""
        with self._locked():
            data = self._read()
            active_id = data.get("active", {}).get(for_py_version)
            if active_id:
                active = next((ApprovalSet.from_dict(i) for i in data["sets"] if i.get("id") == active_id), None)
                if active is not None and active.status == "ready":
                    return active
            ready = [
                ApprovalSet.from_dict(item)
                for item in data.get("sets", [])
                if item.get("status") == "ready" and item.get("for_py_version") == for_py_version
            ]
        return ready[-1] if ready else None

    def select(
        self,
        for_py_version: str,
        approval: Approval | Mapping[str, Any] | str | None = None,
        *,
        offline: bool = True,
        verify: bool = True,
    ) -> ApprovalSelection | None:
        """Select the wheel set an offline creation should reuse.

        When the requested approval has a ready set it is used. Otherwise an
        offline caller gets the last ready set, marked ``stale`` with the actual
        approval identifier. Online callers receive :class:`ApprovalNotFoundError`
        and should run the approved update path instead.

        """
        requested = Approval.load(approval) if not isinstance(approval, Approval) else approval
        requested_id = requested.id if requested is not None else None
        chosen: ApprovalSet | None = None
        stale = False
        reason: str | None = None
        if requested_id is not None:
            chosen = next(
                (record for record in self.sets(for_py_version, status="ready") if record.approval_id == requested_id),
                None,
            )
            if chosen is None:
                if not offline:
                    msg = f"no ready wheel set for approval {requested_id!r} on Python {for_py_version}"
                    raise ApprovalNotFoundError(msg)
                chosen = self.latest_ready(for_py_version)
                if chosen is None:
                    return None
                stale = chosen.approval_id != requested_id
                reason = f"requested approval {requested_id!r} is not ready; reused last ready approval"
        else:
            chosen = self.latest_ready(for_py_version)
        if chosen is None:
            return None
        selection = ApprovalSelection(
            set=chosen,
            app_data=self.app_data,
            requested_approval_id=requested_id,
            offline=offline,
            stale=stale,
            reason=reason,
        )
        if verify:
            self.verify_selection(selection)
        return selection

    def verify_selection(self, selection: ApprovalSelection) -> None:
        """Verify every selected wheel exists in the shared house and matches."""
        house = Path(self.app_data.house)
        for approved in selection.wheels:
            path = house / approved.filename
            if not approved.matches_path(path):
                msg = f"approved wheel {approved.filename!r} is missing or failed its SHA-256 check"
                raise ApprovalIntegrityError(msg)

    def write_receipt(
        self,
        destination: Path | str,
        selection: ApprovalSelection,
        *,
        installed_versions: Mapping[str, str] | None = None,
    ) -> Path:
        """Write a creation receipt into a virtual environment directory."""
        root = Path(getattr(destination, "dest", destination))
        root.mkdir(parents=True, exist_ok=True)
        payload = selection.to_dict()
        if installed_versions:
            payload["installed_versions"] = {
                _canonical_distribution(key): value for key, value in installed_versions.items()
            }
        path = root / RECEIPT_NAME
        temporary = path.with_name(f".{RECEIPT_NAME}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
        return path

    @staticmethod
    def read_receipt(venv: Path | str) -> dict[str, Any]:
        """Read a receipt previously written to a virtual environment."""
        return json.loads((Path(venv) / RECEIPT_NAME).read_text(encoding="utf-8"))

    def _wheel_reference(self, item: ApprovedWheel | Path | str) -> ApprovedWheel:
        if isinstance(item, ApprovedWheel):
            return item
        return ApprovedWheel.from_path(item)

    def _prepare_wheel(self, approval: Approval, item: ApprovedWheel | Path | str) -> ApprovedWheel:
        source = Path(item)
        approved = item if isinstance(item, ApprovedWheel) else ApprovedWheel.from_path(source)
        constraint = approval.wheels.get(approved.distribution)
        if constraint is not None:
            if constraint.filename != approved.filename:
                msg = (
                    f"wheel for {approved.distribution} is {approved.filename!r}, "
                    f"approval {approval.id!r} permits {constraint.filename!r}"
                )
                raise ApprovalError(msg)
            if constraint.sha256 and approved.sha256 and constraint.sha256 != approved.sha256:
                msg = f"SHA-256 for {approved.filename!r} is not permitted by approval {approval.id!r}"
                raise ApprovalIntegrityError(msg)
            if constraint.sha256 and not approved.sha256:
                approved = ApprovedWheel(
                    approved.distribution, approved.filename, approved.version, constraint.sha256
                )
        house = Path(self.app_data.house)
        destination = house / approved.filename
        if source.resolve() != destination.resolve() or not destination.exists():
            house.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp")
            temporary.write_bytes(source.read_bytes())
            os.replace(temporary, destination)
        if approved.sha256 is None:
            approved = ApprovedWheel.from_path(destination)
        elif _sha256(destination) != approved.sha256:
            msg = f"copied wheel {approved.filename!r} failed its SHA-256 check"
            raise ApprovalIntegrityError(msg)
        return approved


ApprovalStore = ApprovalLedger
SeedApproval = Approval


def main(argv: list[str] | None = None) -> int:
    """Run the small JSON command line used by offline approval probes."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m virtualenv.seed.wheels.approval")
    parser.add_argument("--app-data", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--approval", required=True)
    record.add_argument("--for-py-version", required=True)
    record.add_argument("--wheel", nargs="+", required=True)

    begin = subparsers.add_parser("begin")
    begin.add_argument("--approval", required=True)
    begin.add_argument("--for-py-version", required=True)

    commit = subparsers.add_parser("commit")
    commit.add_argument("--set-id", required=True)
    commit.add_argument("--approval")
    commit.add_argument("--wheel", nargs="+", required=True)

    fail = subparsers.add_parser("fail")
    fail.add_argument("--set-id", required=True)
    fail.add_argument("--error", required=True)

    show = subparsers.add_parser("show")
    show.add_argument("--for-py-version", required=True)
    show.add_argument("--approval")

    receipt = subparsers.add_parser("receipt")
    receipt.add_argument("--venv", required=True)

    arguments = parser.parse_args(argv)
    ledger = ApprovalLedger(arguments.app_data)
    try:
        if arguments.command == "record":
            result = ledger.record_update(arguments.approval, arguments.for_py_version, arguments.wheel).to_dict()
        elif arguments.command == "begin":
            result = ledger.begin(arguments.approval, arguments.for_py_version).to_dict()
        elif arguments.command == "commit":
            result = ledger.commit(arguments.set_id, arguments.wheel, arguments.approval).to_dict()
        elif arguments.command == "fail":
            result = ledger.fail(arguments.set_id, arguments.error).to_dict()
        elif arguments.command == "show":
            selection = ledger.select(arguments.for_py_version, arguments.approval)
            result = None if selection is None else selection.to_dict()
        else:
            result = ledger.read_receipt(arguments.venv)
    except ApprovalError as exception:
        print(json.dumps({"error": str(exception)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


__all__ = [
    "APPROVAL_ENV_VARS",
    "APPROVAL_ID_ENV_VARS",
    "RECEIPT_NAME",
    "Approval",
    "ApprovalError",
    "ApprovalIntegrityError",
    "ApprovalLedger",
    "ApprovalNotFoundError",
    "ApprovalSelection",
    "ApprovalSet",
    "ApprovalStore",
    "ApprovedWheel",
    "SeedApproval",
    "load_approval",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
