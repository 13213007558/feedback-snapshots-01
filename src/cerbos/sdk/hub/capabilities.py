# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Scoped Hub access, local transport, and safe publication recovery.

The objects in this module are intentionally transport-level and synchronous
enough to be exercised without a real Cerbos Hub endpoint.  A capability is
bound to one store and a set of actions; an :class:`ApprovalProof` carries the
same scope onto every recorded request.  Recovery never broadens that scope or
silently substitutes another store's credential.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import uuid
import zipfile
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from io import BytesIO
from typing import Any, Protocol

from cerbos.sdk.hub.model import Credentials

_SENSITIVE_KEY_PARTS = ("secret", "token", "password", "credential")
_MISSING = object()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fingerprint(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return _sha256_bytes(raw)[:24]


def _as_tuple(values: Any) -> tuple[Any, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        return (values,)
    return tuple(values)


class HubAction(str, Enum):
    """Actions which can be granted on a Hub store."""

    READ = "read"
    GET_FILES = "get_files"
    LIST_FILES = "list_files"
    WRITE = "write"
    MODIFY_FILES = "modify_files"
    REPLACE_FILES = "replace_files"
    VERIFY = "verify"

    def __str__(self) -> str:
        return self.value


_ACTION_ALIASES = {
    "get": HubAction.GET_FILES.value,
    "getfile": HubAction.GET_FILES.value,
    "getfiles": HubAction.GET_FILES.value,
    "getfilesrequest": HubAction.GET_FILES.value,
    "readfile": HubAction.GET_FILES.value,
    "readfiles": HubAction.GET_FILES.value,
    "list": HubAction.LIST_FILES.value,
    "listfile": HubAction.LIST_FILES.value,
    "listfiles": HubAction.LIST_FILES.value,
    "listfilesrequest": HubAction.LIST_FILES.value,
    "modify": HubAction.MODIFY_FILES.value,
    "modifyfile": HubAction.MODIFY_FILES.value,
    "modifyfiles": HubAction.MODIFY_FILES.value,
    "modifyfilesrequest": HubAction.MODIFY_FILES.value,
    "write": HubAction.WRITE.value,
    "publish": HubAction.MODIFY_FILES.value,
    "release": HubAction.MODIFY_FILES.value,
    "replace": HubAction.REPLACE_FILES.value,
    "replacefile": HubAction.REPLACE_FILES.value,
    "replacefiles": HubAction.REPLACE_FILES.value,
    "replacefilesrequest": HubAction.REPLACE_FILES.value,
    "reconcile": HubAction.VERIFY.value,
    "recovery": HubAction.VERIFY.value,
    "verify": HubAction.VERIFY.value,
    "verifywrite": HubAction.VERIFY.value,
    "add": HubAction.MODIFY_FILES.value,
    "add_or_update": HubAction.MODIFY_FILES.value,
    "update": HubAction.MODIFY_FILES.value,
    "delete": HubAction.MODIFY_FILES.value,
}

_READ_ACTIONS = {
    HubAction.READ.value,
    HubAction.GET_FILES.value,
    HubAction.LIST_FILES.value,
    HubAction.VERIFY.value,
}
_WRITE_ACTIONS = {
    HubAction.WRITE.value,
    HubAction.MODIFY_FILES.value,
    HubAction.REPLACE_FILES.value,
}


def normalize_action(action: HubAction | str) -> str:
    if isinstance(action, HubAction):
        return action.value
    text = str(action).strip()
    key = text.lower().replace("-", "_").replace(" ", "_")
    key = key.replace("__", "_")
    compact = key.replace("_", "")
    if key in {a.value for a in HubAction}:
        return key
    return _ACTION_ALIASES.get(compact, _ACTION_ALIASES.get(key, key))


def action_permits(granted_actions: Iterable[str], requested_action: str) -> bool:
    granted = {normalize_action(a) for a in granted_actions}
    requested = normalize_action(requested_action)
    if "*" in granted:
        return True
    if requested in granted:
        return True
    if HubAction.READ.value in granted and requested in {
        HubAction.GET_FILES.value,
        HubAction.LIST_FILES.value,
        HubAction.VERIFY.value,
    }:
        return True
    if HubAction.VERIFY.value in granted and requested in {
        HubAction.GET_FILES.value,
        HubAction.LIST_FILES.value,
    }:
        return True
    if HubAction.WRITE.value in granted and requested in {
        HubAction.MODIFY_FILES.value,
        HubAction.REPLACE_FILES.value,
        HubAction.VERIFY.value,
    }:
        return True
    return False


class PublicationStatus(str, Enum):
    UNKNOWN = "unknown"
    PENDING = "pending"
    COMMITTED = "committed"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    NOT_PUBLISHED = "not_published"
    DISCARDED = "discarded"
    FAILED = "failed"
    DIVERGED = "diverged"

    def __str__(self) -> str:
        return self.value


class ConfirmationLevel(str, Enum):
    EXACT = "exact"
    STRONG = "strong"
    EXISTENCE_ONLY = "existence_only"
    VERSION_ONLY = "version_only"
    INSUFFICIENT = "insufficient"
    REMOTE_ERROR = "remote_error"
    NONE = "none"

    def __str__(self) -> str:
        return self.value


class HubCapabilityError(Exception):
    """Base class for scope and approval failures."""

    safe_details: Mapping[str, Any]

    def __init__(self, message: str, *, safe_details: Mapping[str, Any] | None = None):
        self.safe_details = dict(safe_details or {})
        super().__init__(message)


class CapabilityDeniedError(HubCapabilityError):
    """Raised before transport when no approved capability covers a request."""


class ApprovalMismatchError(CapabilityDeniedError):
    """Raised when recovery attempts to use a different approval or store."""


class ReplyInterruptedError(Exception):
    """The transport reply was lost after the remote operation may have committed."""

    receipt: RecoveryTicket

    def __init__(self, message: str, *, receipt: RecoveryTicket):
        self.receipt = receipt
        super().__init__(message)

    @property
    def correlation_id(self) -> str:
        return self.receipt.correlation_id

    def safe_details(self) -> dict[str, Any]:
        return self.receipt.safe_dict()


class WriteOutcomeUnknownError(ReplyInterruptedError):
    """Backwards-friendly alias for an interrupted write reply."""


class UnconfirmedPublicationError(Exception):
    def __init__(self, report: ReconciliationReport):
        self.report = report
        super().__init__(
            f"publication {report.correlation_id} is {report.status.value}: "
            f"{report.reason}"
        )


@dataclass(frozen=True)
class OperationSpec:
    """One actual file operation sent (or about to be sent) to Hub."""

    action: str
    path: str
    contents: bytes | None = field(default=None, repr=False)
    content_sha256: str | None = None
    size: int | None = None
    rpc_action: str | None = None

    def __post_init__(self) -> None:
        action = str(self.action)
        if action in {"add_or_update", "upsert", "update"}:
            normalized = "add"
            rpc_action = "add_or_update"
        else:
            normalized = action
            rpc_action = action if self.rpc_action is None else self.rpc_action
        object.__setattr__(self, "action", normalized)
        object.__setattr__(self, "rpc_action", rpc_action)
        if self.contents is not None:
            if not isinstance(self.contents, bytes):
                object.__setattr__(self, "contents", bytes(self.contents))
            object.__setattr__(self, "size", len(self.contents))
            object.__setattr__(self, "content_sha256", _sha256_bytes(self.contents))
        elif self.size is None:
            object.__setattr__(self, "size", None)

    @property
    def op(self) -> str:
        return self.action

    @property
    def kind(self) -> str:
        return self.action

    @property
    def sha256(self) -> str | None:
        return self.content_sha256

    def safe_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "rpc_action": self.rpc_action,
            "path": self.path,
            "sha256": self.content_sha256,
            "size": self.size,
        }


def operation_specs_from_file_ops(file_ops: Any) -> tuple[OperationSpec, ...]:
    if file_ops is None:
        return ()
    if isinstance(file_ops, (list, tuple)):
        candidates = tuple(file_ops)
    elif hasattr(file_ops, "add") or hasattr(file_ops, "delete"):
        candidates = ()
        add = getattr(file_ops, "add", None)
        delete = getattr(file_ops, "delete", None)
        for file in add or ():
            path = getattr(file, "path", None)
            contents = getattr(file, "contents", None)
            if isinstance(file, Mapping):
                path = file.get("path", path)
                contents = file.get("contents", contents)
            candidates += (OperationSpec("add", str(path), contents),)
        for path in delete or ():
            candidates += (OperationSpec("delete", str(path)),)
        return candidates
    else:
        candidates = tuple(file_ops)

    operations: list[OperationSpec] = []
    for item in candidates:
        if isinstance(item, OperationSpec):
            operations.append(item)
        elif isinstance(item, Mapping):
            operations.append(
                OperationSpec(
                    str(item.get("action") or item.get("op") or "add"),
                    str(item["path"]),
                    item.get("contents"),
                )
            )
        elif isinstance(item, tuple) and len(item) >= 2:
            operations.append(OperationSpec(str(item[0]), str(item[1]), item[2] if len(item) > 2 else None))
        else:
            path = getattr(item, "path", None)
            contents = getattr(item, "contents", None)
            action = getattr(item, "action", "add")
            operations.append(OperationSpec(str(action), str(path), contents))
    return tuple(operations)


def replace_operation_specs(
    contents: bytes | Iterable[Any],
) -> tuple[OperationSpec, ...]:
    if isinstance(contents, bytes):
        operations: list[OperationSpec] = []
        with zipfile.ZipFile(BytesIO(contents)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                operations.append(
                    OperationSpec("add", info.filename, archive.read(info))
                )
        return tuple(operations)
    return operation_specs_from_file_ops(contents)


@dataclass(frozen=True)
class ApprovalProof:
    """Shareable approval evidence bound to a store and actions."""

    approval_id: str
    store_id: str
    actions: frozenset[str] = field(default_factory=frozenset)
    identity: str | None = None
    proof_token: str | None = field(default=None, repr=False)
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        normalized = frozenset(normalize_action(a) for a in self.actions)
        object.__setattr__(self, "actions", normalized)

    @property
    def proof_id(self) -> str:
        return self.approval_id

    @property
    def id(self) -> str:
        return self.approval_id

    @property
    def store(self) -> str:
        return self.store_id

    @property
    def repo(self) -> str:
        return self.store_id

    @property
    def repository(self) -> str:
        return self.store_id

    @property
    def token(self) -> str | None:
        return self.proof_token

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            [
                self.approval_id,
                self.store_id,
                sorted(self.actions),
                self.identity,
                _sha256_bytes(self.proof_token.encode()) if self.proof_token else None,
            ]
        )

    def permits(self, action: str, store_id: str | None = None) -> bool:
        if store_id is not None and store_id != self.store_id:
            return False
        return action_permits(self.actions, action)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "proof_id": self.approval_id,
            "proof_fingerprint": self.fingerprint,
            "store_id": self.store_id,
            "actions": sorted(self.actions),
            "identity": self.identity,
            "correlation_id": self.correlation_id,
        }

    def redacted(self) -> dict[str, Any]:
        return self.safe_dict()


@dataclass(frozen=True)
class HubCapability:
    """Optional authority constraint for Hub access."""

    store_id: str
    actions: frozenset[str] = field(default_factory=frozenset)
    proof: ApprovalProof | None = None
    identity: str | None = None
    credential_ref: str | None = None
    capability_id: str = field(default_factory=lambda: _new_id("cap"))

    def __post_init__(self) -> None:
        actions = set(self.actions)
        if self.proof is not None:
            if self.proof.store_id not in {self.store_id, "*"} and self.store_id != "*":
                if self.proof.store_id != self.store_id:
                    raise ApprovalMismatchError(
                        "approval proof is bound to another store",
                        safe_details={
                            "capability_store_id": self.store_id,
                            "proof_store_id": self.proof.store_id,
                        },
                    )
            actions.update(self.proof.actions)
            if self.identity is None and self.proof.identity is not None:
                object.__setattr__(self, "identity", self.proof.identity)
        object.__setattr__(
            self, "actions", frozenset(normalize_action(a) for a in actions)
        )

    @property
    def store(self) -> str:
        return self.store_id

    @property
    def repo(self) -> str:
        return self.store_id

    @property
    def repository(self) -> str:
        return self.store_id

    def permits(
        self,
        action: str,
        store_id: str | None = None,
        *,
        identity: str | None = None,
        credential_ref: str | None = None,
    ) -> bool:
        if store_id is not None and self.store_id != "*" and store_id != self.store_id:
            return False
        if not action_permits(self.actions, action):
            return False
        if self.identity and identity and self.identity != identity:
            return False
        if (
            self.credential_ref
            and credential_ref
            and self.credential_ref != credential_ref
        ):
            return False
        return True

    def authorize(self, request: HubRequest) -> None:
        details = {
            "store_id": request.store_id,
            "action": normalize_action(request.action),
            "capability_id": self.capability_id,
        }
        if self.store_id != "*" and request.store_id != self.store_id:
            raise CapabilityDeniedError(
                "Hub capability is not approved for this store",
                safe_details={**details, "approved_store_id": self.store_id},
            )
        if not action_permits(self.actions, request.action):
            raise CapabilityDeniedError(
                "Hub capability does not permit this action",
                safe_details={**details, "approved_actions": sorted(self.actions)},
            )
        request_identity = request.identity
        if self.identity and request_identity and self.identity != request_identity:
            raise CapabilityDeniedError(
                "Hub capability is approved for another identity",
                safe_details={
                    **details,
                    "approved_identity": self.identity,
                    "actual_identity": request_identity,
                },
            )
        if (
            self.credential_ref
            and request.credential_ref
            and self.credential_ref != request.credential_ref
        ):
            raise ApprovalMismatchError(
                "recovery credential reference does not match the approved capability",
                safe_details={
                    **details,
                    "approved_credential_ref": self.credential_ref,
                    "actual_credential_ref": request.credential_ref,
                },
            )
        if self.proof is not None and request.proof is not None:
            if self.proof.fingerprint != request.proof.fingerprint:
                raise ApprovalMismatchError(
                    "request carries a different approval proof",
                    safe_details={
                        **details,
                        "expected_proof_fingerprint": self.proof.fingerprint,
                        "actual_proof_fingerprint": request.proof.fingerprint,
                    },
                )

    def safe_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "store_id": self.store_id,
            "actions": sorted(self.actions),
            "identity": self.identity,
            "credential_ref": self.credential_ref,
            "proof": self.proof.safe_dict() if self.proof else None,
        }


class HubAccessPolicy:
    """Collection of capabilities; request must match at least one grant."""

    def __init__(self, capabilities: HubCapability | Iterable[HubCapability] | None = None):
        if capabilities is None:
            values: tuple[HubCapability, ...] = ()
        elif isinstance(capabilities, HubCapability):
            values = (capabilities,)
        else:
            values = tuple(capabilities)
        self.capabilities = values

    def select(self, request: HubRequest) -> HubCapability:
        last_error: CapabilityDeniedError | None = None
        for capability in self.capabilities:
            try:
                capability.authorize(request)
                return capability
            except CapabilityDeniedError as exc:
                last_error = exc
        details = request.safe_dict()
        if last_error is not None:
            details["last_denial"] = last_error.safe_details
            for key, value in last_error.safe_details.items():
                details.setdefault(key, value)
        raise CapabilityDeniedError(
            "no approved Hub capability covers this request",
            safe_details=details,
        )

    def prepare(self, request: HubRequest) -> HubRequest:
        candidate = replace(request)
        if candidate.proof is None:
            for capability in self.capabilities:
                if capability.permits(
                    candidate.action,
                    candidate.store_id,
                    identity=candidate.identity,
                    credential_ref=candidate.credential_ref,
                ):
                    candidate = replace(candidate, capability=capability)
                    if capability.proof is not None:
                        candidate = replace(candidate, proof=capability.proof)
                    capability.authorize(candidate)
                    return candidate
        capability = self.select(candidate)
        candidate = replace(candidate, capability=capability)
        capability.authorize(candidate)
        return candidate


@dataclass
class CredentialSource:
    """A separately refreshable credential source for one Hub identity."""

    credentials: Credentials | None = None
    refresher: Callable[..., Credentials | Mapping[str, str] | str | None] | None = None
    ref: str | None = None
    identity: str | None = None
    generation: int = 0

    def __post_init__(self) -> None:
        if callable(self.credentials) and self.refresher is None:
            self.refresher = self.credentials  # type: ignore[assignment]
            self.credentials = None

    @property
    def current_credentials(self) -> Credentials | None:
        if self.credentials is None and self.refresher is not None:
            refreshed = self._call_refresher()
            self.credentials = self._coerce_credentials(refreshed)
        return self.credentials

    def _call_refresher(self) -> Any:
        assert self.refresher is not None
        try:
            parameters = inspect.signature(self.refresher).parameters
        except (TypeError, ValueError):
            return self.refresher()
        if len(parameters) >= 1:
            return self.refresher(self.credentials)
        return self.refresher()

    @staticmethod
    def _coerce_credentials(value: Any) -> Credentials | None:
        if value is None or isinstance(value, Credentials):
            return value
        if isinstance(value, Mapping):
            return Credentials(
                str(value.get("client_id", "")),
                str(value.get("client_secret", "")),
            )
        if isinstance(value, tuple) and len(value) >= 2:
            return Credentials(str(value[0]), str(value[1]))
        raise TypeError("credential refresher must return Credentials or a mapping")

    def get(self) -> Credentials | None:
        return self.current_credentials

    def refresh(self, credentials: Credentials | Mapping[str, str] | None = None) -> Credentials | None:
        if credentials is not None:
            self.credentials = self._coerce_credentials(credentials)
        elif self.refresher is not None:
            self.credentials = self._coerce_credentials(self._call_refresher())
        self.generation += 1
        return self.credentials

    update_credentials = refresh

    @property
    def client_id(self) -> str | None:
        credentials = self.current_credentials
        return credentials.client_id if credentials else None

    @property
    def identity_name(self) -> str | None:
        if self.identity is not None:
            return self.identity
        return self.client_id

    def descriptor(self) -> dict[str, Any]:
        credentials = self.current_credentials
        return {
            "credential_ref": self.ref,
            "identity": self.identity_name,
            "client_id": credentials.client_id if credentials else None,
            "generation": self.generation,
        }


class CredentialVault:
    """Named credential sources; recovery selects the ticket's original ref."""

    def __init__(
        self,
        sources: Mapping[str, CredentialSource | Credentials] | None = None,
        *,
        active_ref: str | None = None,
    ):
        self._sources: dict[str, CredentialSource] = {}
        for ref, source in (sources or {}).items():
            self.add(ref, source)
        self.active_ref = active_ref

    def add(
        self,
        ref: str,
        source: CredentialSource | Credentials,
        *,
        activate: bool = False,
    ) -> CredentialSource:
        if not isinstance(source, CredentialSource):
            source = CredentialSource(source, ref=ref)
        if source.ref is None:
            source.ref = ref
        self._sources[ref] = source
        if activate or self.active_ref is None:
            self.active_ref = ref
        return source

    def get(self, ref: str) -> CredentialSource:
        try:
            return self._sources[ref]
        except KeyError:
            raise CapabilityDeniedError(
                "recovery credential reference is not present in vault",
                safe_details={"credential_ref": ref},
            ) from None

    def use(self, ref: str) -> CredentialSource:
        source = self.get(ref)
        self.active_ref = ref
        return source

    @property
    def active(self) -> CredentialSource:
        if self.active_ref is None:
            raise CapabilityDeniedError("no active Hub credential is configured")
        return self.get(self.active_ref)


@dataclass
class HubRequest:
    action: str
    store_id: str
    operations: tuple[OperationSpec, ...] = ()
    paths: tuple[str, ...] = ()
    message: str | None = None
    expected_version: int | None = None
    idempotency_key: str | None = None
    correlation_id: str = field(default_factory=lambda: _new_id("corr"))
    proof: ApprovalProof | None = None
    capability: HubCapability | None = None
    credentials: Credentials | None = field(default=None, repr=False)
    credential_ref: str | None = None
    identity: str | None = None
    credential_generation: int = 0
    metadata: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        self.action = normalize_action(self.action)
        self.paths = tuple(self.paths)
        self.operations = tuple(self.operations)

    @property
    def repo(self) -> str:
        return self.store_id

    @property
    def repository(self) -> str:
        return self.store_id

    @property
    def approval_proof(self) -> ApprovalProof | None:
        return self.proof

    @approval_proof.setter
    def approval_proof(self, value: ApprovalProof | None) -> None:
        self.proof = value

    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "action": self.action,
                "store_id": self.store_id,
                "operations": [op.safe_dict() for op in self.operations],
                "paths": list(self.paths),
                "expected_version": self.expected_version,
                "idempotency_key": self.idempotency_key,
                "message": self.message,
            }
        )

    def safe_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "store_id": self.store_id,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "expected_version": self.expected_version,
            "operations": [op.safe_dict() for op in self.operations],
            "paths": list(self.paths),
            "credential_ref": self.credential_ref,
            "identity": self.identity,
            "credential_generation": self.credential_generation,
            "approval": self.proof.safe_dict() if self.proof else None,
        }


@dataclass
class HubResponse:
    action: str
    store_id: str
    version: int | None = None
    files: dict[str, bytes | None] = field(default_factory=dict)
    paths: tuple[str, ...] = ()
    committed: bool = False
    deduplicated: bool = False
    confirmation_level: ConfirmationLevel = ConfirmationLevel.EXACT
    commit_correlation_id: str | None = None
    request: HubRequest | None = None

    @property
    def store_version(self) -> int | None:
        return self.version

    @property
    def new_store_version(self) -> int | None:
        return self.version

    def files_as_map(self) -> Mapping[str, bytes]:
        return {
            path: contents
            for path, contents in self.files.items()
            if contents is not None
        }

    def present_paths(self) -> list[str]:
        if self.paths:
            return list(self.paths)
        return list(self.files.keys())


@dataclass(frozen=True)
class RecoveryTicket:
    correlation_id: str
    store_id: str
    action: str
    idempotency_key: str | None = None
    operations: tuple[OperationSpec, ...] = ()
    paths: tuple[str, ...] = ()
    expected_version: int | None = None
    proof: ApprovalProof | None = None
    capability: HubCapability | None = None
    credential_ref: str | None = None
    created_at: str | None = None

    @classmethod
    def from_request(cls, request: HubRequest) -> RecoveryTicket:
        safe_operations = tuple(
            replace(operation, contents=None) for operation in request.operations
        )
        paths = request.paths or tuple(
            dict.fromkeys(operation.path for operation in request.operations)
        )
        return cls(
            correlation_id=request.correlation_id,
            idempotency_key=request.idempotency_key,
            store_id=request.store_id,
            action=request.action,
            operations=safe_operations,
            paths=tuple(paths),
            expected_version=request.expected_version,
            proof=request.proof,
            capability=request.capability,
            credential_ref=request.credential_ref,
        )

    @property
    def receipt(self) -> RecoveryTicket:
        return self

    def safe_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "store_id": self.store_id,
            "action": normalize_action(self.action),
            "expected_version": self.expected_version,
            "operations": [op.safe_dict() for op in self.operations],
            "paths": list(self.paths),
            "credential_ref": self.credential_ref,
            "approval": self.proof.safe_dict() if self.proof else None,
            "capability_id": self.capability.capability_id if self.capability else None,
        }


@dataclass(frozen=True)
class OperationCheck:
    path: str
    action: str
    status: str
    matched: bool | None
    reason: str
    expected_sha256: str | None = None
    observed_sha256: str | None = None
    path_present: bool | None = None

    def safe_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "action": self.action,
            "status": self.status,
            "matched": self.matched,
            "reason": self.reason,
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
            "path_present": self.path_present,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    status: PublicationStatus
    confirmation: ConfirmationLevel
    ticket: RecoveryTicket
    checks: tuple[OperationCheck, ...] = ()
    observed_version: int | None = None
    reason: str = ""
    next_action: str = "manual_confirmation"
    safe_to_continue: bool = False
    safe_to_retry: bool = False
    requires_manual_confirmation: bool = True

    @property
    def correlation_id(self) -> str:
        return self.ticket.correlation_id

    @property
    def store_id(self) -> str:
        return self.ticket.store_id

    @property
    def approval_id(self) -> str | None:
        return self.ticket.proof.approval_id if self.ticket.proof else None

    @property
    def identity(self) -> str | None:
        if self.ticket.capability and self.ticket.capability.identity:
            return self.ticket.capability.identity
        return self.ticket.proof.identity if self.ticket.proof else None

    @property
    def is_confirmed(self) -> bool:
        return self.status == PublicationStatus.CONFIRMED

    @property
    def is_unconfirmed(self) -> bool:
        return self.status in {
            PublicationStatus.UNCONFIRMED,
            PublicationStatus.DIVERGED,
            PublicationStatus.FAILED,
        }

    def __bool__(self) -> bool:
        return self.is_confirmed

    @property
    def diagnostic(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "idempotency_key": self.ticket.idempotency_key,
            "store_id": self.store_id,
            "action": normalize_action(self.ticket.action),
            "approval_id": self.approval_id,
            "proof_fingerprint": (
                self.ticket.proof.fingerprint if self.ticket.proof else None
            ),
            "identity": self.identity,
            "credential_ref": self.ticket.credential_ref,
            "status": self.status.value,
            "confirmation": self.confirmation.value,
            "reason": self.reason,
            "next_action": self.next_action,
            "observed_version": self.observed_version,
        }

    def safe_dict(self) -> dict[str, Any]:
        diagnostic = self.diagnostic
        diagnostic["checks"] = [check.safe_dict() for check in self.checks]
        diagnostic["safe_to_continue"] = self.safe_to_continue
        diagnostic["safe_to_retry"] = self.safe_to_retry
        diagnostic["requires_manual_confirmation"] = (
            self.requires_manual_confirmation
        )
        return diagnostic

    def raise_if_unconfirmed(self) -> None:
        if not self.is_confirmed:
            raise UnconfirmedPublicationError(self)


@dataclass
class PublicationResult:
    status: PublicationStatus
    response: HubResponse | None = None
    receipt: RecoveryTicket | None = None
    report: ReconciliationReport | None = None
    error: BaseException | None = None

    @property
    def is_unconfirmed(self) -> bool:
        return self.status == PublicationStatus.UNCONFIRMED

    @property
    def safe_to_continue(self) -> bool:
        if self.report is not None:
            return self.report.safe_to_continue
        return self.status == PublicationStatus.CONFIRMED

    def new_store_version(self) -> int | None:
        if self.report and self.report.observed_version is not None:
            return self.report.observed_version
        if self.response:
            return self.response.version
        return None

    def safe_dict(self) -> dict[str, Any]:
        if self.report:
            return self.report.safe_dict()
        if self.receipt:
            return {"status": self.status.value, **self.receipt.safe_dict()}
        return {"status": self.status.value}


class HubTransport(Protocol):
    def send(self, request: HubRequest) -> HubResponse | Awaitable[HubResponse]: ...


@dataclass
class _StoreState:
    files: dict[str, bytes]
    version: int = 0


@dataclass(frozen=True)
class CommitRecord:
    commit_id: str
    correlation_id: str
    idempotency_key: str | None
    store_id: str
    action: str
    version: int
    request_fingerprint: str
    proof_fingerprint: str | None
    operations: tuple[dict[str, Any], ...]


class LocalHubTransport:
    """In-memory Hub transport with an explicit reply-loss hook."""

    def __init__(
        self,
        stores: Mapping[str, Mapping[str, bytes] | _StoreState] | None = None,
        *,
        files: Mapping[str, Mapping[str, bytes] | _StoreState] | None = None,
        interrupted_stores: Iterable[str] | str | None = None,
        interrupted_actions: Iterable[str] | str | None = None,
        lost_replies: Iterable[Any] | None = None,
        interrupt_reply: Callable[[HubRequest], bool] | None = None,
        confirmation: str | Mapping[str, str] = ConfirmationLevel.EXACT.value,
        confirmation_policy: str | Mapping[str, str] | None = None,
        delay: float = 0.0,
        lose_reply_once: bool = True,
    ):
        source_stores = stores if stores is not None else files
        self.states: dict[str, _StoreState] = {}
        for store_id, store_files in (source_stores or {}).items():
            if isinstance(store_files, _StoreState):
                self.states[store_id] = store_files
            else:
                self.states[store_id] = _StoreState(dict(store_files), version=1)
        if not self.states:
            self.states = {"A": _StoreState({}, 1), "B": _StoreState({}, 1)}

        self.requests: list[HubRequest] = []
        self.commits: list[CommitRecord] = []
        self._commits_by_idempotency: dict[str, CommitRecord] = {}
        self._responses_by_idempotency: dict[str, HubResponse] = {}
        self.delay = delay
        self.lose_reply_once = lose_reply_once
        self._consumed_losses: set[tuple[str, str]] = set()
        self._interrupt_reply = interrupt_reply
        self.lost_replies = list(lost_replies or [])

        if isinstance(interrupted_stores, str):
            interrupted_stores = {interrupted_stores}
        self.interrupted_stores = set(interrupted_stores or ())
        if isinstance(interrupted_actions, str):
            interrupted_actions = {interrupted_actions}
        self.interrupted_actions = {
            normalize_action(action) for action in (interrupted_actions or ())
        }
        policy = confirmation_policy or confirmation
        self.confirmation_policy = policy

    @property
    def sent(self) -> list[HubRequest]:
        return self.requests

    @property
    def calls(self) -> list[HubRequest]:
        return self.requests

    @property
    def sent_requests(self) -> list[HubRequest]:
        return self.requests

    @property
    def recorded_requests(self) -> list[HubRequest]:
        return self.requests

    def reset_requests(self) -> None:
        self.requests.clear()

    def seed(
        self, store_id: str, files: Mapping[str, bytes] | None = None, version: int = 1
    ) -> None:
        self.states[store_id] = _StoreState(dict(files or {}), version)

    def store(self, store_id: str) -> _StoreState:
        try:
            return self.states[store_id]
        except KeyError:
            raise CapabilityDeniedError(
                "local Hub transport has no such store",
                safe_details={"store_id": store_id},
            ) from None

    def confirmation_for(self, store_id: str) -> ConfirmationLevel:
        if isinstance(self.confirmation_policy, Mapping):
            value = self.confirmation_policy.get(
                store_id,
                self.confirmation_policy.get("*", ConfirmationLevel.EXACT.value),
            )
        else:
            value = self.confirmation_policy
        value = str(value)
        if value in {
            ConfirmationLevel.EXACT.value,
            ConfirmationLevel.STRONG.value,
        }:
            return ConfirmationLevel.EXACT
        if value in {
            ConfirmationLevel.EXISTENCE_ONLY.value,
            "weak",
            "insufficient",
            "content_hidden",
        }:
            return ConfirmationLevel.EXISTENCE_ONLY
        if value in {ConfirmationLevel.VERSION_ONLY.value, "version"}:
            return ConfirmationLevel.VERSION_ONLY
        return ConfirmationLevel.INSUFFICIENT

    def _should_lose_reply(self, request: HubRequest) -> bool:
        if self._interrupt_reply is not None:
            return bool(self._interrupt_reply(request))
        for rule in self.lost_replies:
            if self._rule_matches(rule, request):
                return True
        store_match = (
            not self.interrupted_stores or request.store_id in self.interrupted_stores
        )
        action_match = (
            not self.interrupted_actions
            or request.action in self.interrupted_actions
        )
        if not (store_match and action_match):
            return False
        loss_key = (request.store_id, request.action)
        if self.lose_reply_once and loss_key in self._consumed_losses:
            return False
        self._consumed_losses.add(loss_key)
        return True

    @staticmethod
    def _rule_matches(rule: Any, request: HubRequest) -> bool:
        if callable(rule):
            return bool(rule(request))
        if isinstance(rule, Mapping):
            store = rule.get("store_id") or rule.get("store") or rule.get("repo")
            action = rule.get("action")
            return (store is None or store == request.store_id) and (
                action is None or normalize_action(action) == request.action
            )
        if isinstance(rule, (tuple, list)):
            if len(rule) == 1:
                return rule[0] == request.store_id
            return rule[0] == request.store_id and normalize_action(rule[1]) == request.action
        return False

    def send(self, request: HubRequest) -> HubResponse:
        return self.handle(request)

    def send_sync(self, request: HubRequest) -> HubResponse:
        return self.handle(request)

    async def asend(self, request: HubRequest) -> HubResponse:
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.handle(request)

    async def send_async(self, request: HubRequest) -> HubResponse:
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.handle(request)

    def handle(self, request: HubRequest) -> HubResponse:
        self.requests.append(request)
        action = normalize_action(request.action)
        state = self.store(request.store_id)
        confirmation = self.confirmation_for(request.store_id)

        if action == HubAction.GET_FILES.value:
            return self._handle_get(request, state, confirmation)
        if action == HubAction.LIST_FILES.value:
            paths = tuple(sorted(state.files))
            if confirmation == ConfirmationLevel.VERSION_ONLY:
                paths = ()
            return HubResponse(
                action=action,
                store_id=request.store_id,
                version=state.version,
                paths=paths,
                files={},
                confirmation_level=confirmation,
                request=request,
            )
        if action in {
            HubAction.MODIFY_FILES.value,
            HubAction.REPLACE_FILES.value,
        }:
            return self._handle_write(request, state, action)
        raise CapabilityDeniedError(
            "local Hub transport does not implement action",
            safe_details=request.safe_dict(),
        )

    def _handle_get(
        self,
        request: HubRequest,
        state: _StoreState,
        confirmation: ConfirmationLevel,
    ) -> HubResponse:
        files: dict[str, bytes | None] = {}
        paths: list[str] = []
        for path in request.paths:
            if path not in state.files:
                continue
            paths.append(path)
            if confirmation == ConfirmationLevel.EXACT:
                files[path] = state.files[path]
            else:
                files[path] = None
        return HubResponse(
            action=request.action,
            store_id=request.store_id,
            version=state.version,
            files=files,
            paths=tuple(paths),
            confirmation_level=confirmation,
            request=request,
        )

    def _handle_write(
        self, request: HubRequest, state: _StoreState, action: str
    ) -> HubResponse:
        if request.idempotency_key:
            existing = self._commits_by_idempotency.get(request.idempotency_key)
            if existing is not None:
                if existing.request_fingerprint != request.fingerprint():
                    raise CapabilityDeniedError(
                        "idempotency key was reused with different operations",
                        safe_details={
                            "correlation_id": request.correlation_id,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                response = replace(
                    self._responses_by_idempotency[request.idempotency_key],
                    deduplicated=True,
                    request=request,
                )
                return response

        if not request.operations:
            raise CapabilityDeniedError(
                "file operations list is empty",
                safe_details={"correlation_id": request.correlation_id},
            )

        if action == HubAction.REPLACE_FILES.value:
            state.files.clear()
        for operation in request.operations:
            if operation.action == "delete":
                state.files.pop(operation.path, None)
            else:
                state.files[operation.path] = operation.contents or b""
        state.version += 1

        proof_fingerprint = request.proof.fingerprint if request.proof else None
        commit = CommitRecord(
            commit_id=_new_id("commit"),
            correlation_id=request.correlation_id,
            idempotency_key=request.idempotency_key,
            store_id=request.store_id,
            action=action,
            version=state.version,
            request_fingerprint=request.fingerprint(),
            proof_fingerprint=proof_fingerprint,
            operations=tuple(op.safe_dict() for op in request.operations),
        )
        self.commits.append(commit)
        if request.idempotency_key:
            self._commits_by_idempotency[request.idempotency_key] = commit

        response = HubResponse(
            action=action,
            store_id=request.store_id,
            version=state.version,
            committed=True,
            commit_correlation_id=request.correlation_id,
            request=request,
        )
        if request.idempotency_key:
            self._responses_by_idempotency[request.idempotency_key] = response

        if self._should_lose_reply(request):
            ticket = RecoveryTicket.from_request(request)
            raise WriteOutcomeUnknownError(
                "Hub write committed but the reply was interrupted",
                receipt=ticket,
            )
        return response


def _credential_source_from_constructor(
    credentials: Any,
    *,
    credential_source: CredentialSource | None,
    vault: CredentialVault | None,
    credential_ref: str | None,
) -> CredentialSource | None:
    if credential_source is not None:
        return credential_source
    if credential_ref is not None and vault is not None:
        return vault.get(credential_ref)
    if credentials is None:
        return None
    if isinstance(credentials, CredentialSource):
        return credentials
    return CredentialSource(credentials, ref=credential_ref)


class _BaseGuardedHubClient:
    def __init__(
        self,
        transport: HubTransport | Any,
        capability: HubCapability | None = None,
        *,
        capabilities: HubCapability | Iterable[HubCapability] | None = None,
        credentials: Credentials | CredentialSource | Callable[..., Any] | None = None,
        credential_source: CredentialSource | None = None,
        vault: CredentialVault | None = None,
        credential_ref: str | None = None,
        **options: Any,
    ):
        if capability is None:
            for key in ("grant", "scope", "permission", "capability_constraint"):
                if key in options:
                    capability = options.pop(key)
                    break
        if capabilities is None:
            for key in (
                "grants",
                "scopes",
                "permissions",
                "capability_constraints",
            ):
                if key in options:
                    capabilities = options.pop(key)
                    break
        policy = options.pop("policy", None) or options.pop("access_policy", None)
        if isinstance(policy, HubAccessPolicy):
            capabilities = policy.capabilities
        elif capabilities is None and policy is not None:
            capabilities = policy

        credential_provider = options.pop("credential_provider", None)
        if credential_source is None and credential_provider is not None:
            credential_source = CredentialSource(
                refresher=credential_provider,
                ref=credential_ref,
            )

        self.transport = transport
        all_capabilities: list[HubCapability] = []
        if capability is not None:
            all_capabilities.append(capability)
        if capabilities is not None:
            if isinstance(capabilities, HubCapability):
                all_capabilities.append(capabilities)
            else:
                all_capabilities.extend(capabilities)
        self.policy = HubAccessPolicy(all_capabilities) if all_capabilities else None
        self.vault = vault
        self.credential_ref = credential_ref or (
            capability.credential_ref if capability else None
        )
        self.credential_source = _credential_source_from_constructor(
            credentials,
            credential_source=credential_source,
            vault=vault,
            credential_ref=self.credential_ref,
        )
        if self.credential_source is not None and self.credential_ref:
            self.credential_source.ref = self.credential_ref

    def refresh_credentials(
        self, credentials: Credentials | Mapping[str, str] | None = None
    ) -> Credentials | None:
        if self.credential_source is None:
            self.credential_source = CredentialSource(ref=self.credential_ref)
        return self.credential_source.refresh(credentials)

    def _active_source(self, credential_ref: str | None = None) -> CredentialSource | None:
        ref = credential_ref or self.credential_ref
        if self.vault is not None and ref is not None:
            return self.vault.get(ref)
        if self.credential_source is not None:
            if ref and self.credential_source.ref and ref != self.credential_source.ref:
                raise ApprovalMismatchError(
                    "cannot substitute another credential reference during recovery",
                    safe_details={
                        "requested_credential_ref": ref,
                        "bound_credential_ref": self.credential_source.ref,
                    },
                )
            return self.credential_source
        return None

    def _build_request(
        self,
        action: str,
        store_id: str,
        *,
        operations: Iterable[OperationSpec] = (),
        paths: Iterable[str] = (),
        message: str | None = None,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
        capability: HubCapability | None = None,
        proof: ApprovalProof | None = None,
        credential_ref: str | None = None,
    ) -> HubRequest:
        source = self._active_source(credential_ref)
        descriptor = source.descriptor() if source else {}
        request = HubRequest(
            action=action,
            store_id=store_id,
            operations=tuple(operations),
            paths=tuple(paths),
            message=message,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id or _new_id("corr"),
            proof=proof,
            credential_ref=descriptor.get("credential_ref") or credential_ref,
            identity=descriptor.get("identity"),
            credential_generation=descriptor.get("generation", 0),
            credentials=source.get() if source else None,
        )
        scoped_capability = capability
        if scoped_capability is not None:
            if scoped_capability.proof is not None and request.proof is None:
                request.proof = scoped_capability.proof
            request.capability = scoped_capability
            scoped_capability.authorize(request)
            return request
        if proof is not None:
            request.proof = proof
        if self.policy is not None:
            request = self.policy.prepare(request)
        return request

    def _build_recovery_request(
        self,
        ticket: RecoveryTicket,
        action: str,
        *,
        paths: Iterable[str] = (),
        credential_ref: str | None = None,
    ) -> HubRequest:
        capability = ticket.capability
        if capability is None:
            raise ApprovalMismatchError(
                "recovery ticket has no approved capability",
                safe_details={"correlation_id": ticket.correlation_id},
            )
        source = self._recovery_source(ticket, credential_ref)
        descriptor = source.descriptor() if source else {}
        request = HubRequest(
            action=action,
            store_id=ticket.store_id,
            paths=tuple(paths),
            correlation_id=ticket.correlation_id,
            proof=ticket.proof or capability.proof,
            capability=capability,
            credential_ref=ticket.credential_ref,
            identity=descriptor.get("identity") or capability.identity,
            credential_generation=descriptor.get("generation", 0),
            credentials=source.get() if source else None,
        )
        capability.authorize(request)
        return request

    def _recovery_source(
        self,
        ticket: RecoveryTicket,
        credential_ref: str | None = None,
    ) -> CredentialSource | None:
        requested_ref = credential_ref or ticket.credential_ref
        if credential_ref and ticket.credential_ref and credential_ref != ticket.credential_ref:
            raise ApprovalMismatchError(
                "recovery cannot use a credential reference outside the approved ticket",
                safe_details={
                    "correlation_id": ticket.correlation_id,
                    "ticket_credential_ref": ticket.credential_ref,
                    "requested_credential_ref": credential_ref,
                },
            )
        if requested_ref:
            if self.vault is not None:
                return self.vault.get(requested_ref)
            if self.credential_source is not None:
                source_ref = self.credential_source.ref or self.credential_ref
                if source_ref and source_ref != requested_ref:
                    raise ApprovalMismatchError(
                        "recovery must use the credential approved for the original request",
                        safe_details={
                            "correlation_id": ticket.correlation_id,
                            "ticket_credential_ref": requested_ref,
                            "active_credential_ref": source_ref,
                        },
                    )
                return self.credential_source
            raise ApprovalMismatchError(
                "recovery credential source is unavailable",
                safe_details={"credential_ref": requested_ref},
            )
        return self.credential_source

    @staticmethod
    def _idempotency_key(
        store_id: str, action: str, operations: tuple[OperationSpec, ...]
    ) -> str:
        return "idem_" + _fingerprint(
            {
                "store_id": store_id,
                "action": normalize_action(action),
                "operations": [op.safe_dict() for op in operations],
            }
        )

    @staticmethod
    def _ticket_from(error_or_ticket: RecoveryTicket | BaseException) -> RecoveryTicket:
        if isinstance(error_or_ticket, RecoveryTicket):
            return error_or_ticket
        ticket = getattr(error_or_ticket, "receipt", None)
        if isinstance(ticket, RecoveryTicket):
            return ticket
        raise TypeError("expected a RecoveryTicket or ReplyInterruptedError")

    def _evaluate_responses(
        self,
        ticket: RecoveryTicket,
        list_response: HubResponse | None,
        get_response: HubResponse | None,
        transport_error: Exception | None = None,
    ) -> ReconciliationReport:
        if transport_error is not None:
            return ReconciliationReport(
                status=PublicationStatus.UNCONFIRMED,
                confirmation=ConfirmationLevel.REMOTE_ERROR,
                ticket=ticket,
                reason="remote verification failed",
                next_action="retry_verification_with_same_scope",
                safe_to_continue=False,
                requires_manual_confirmation=True,
            )

        listed_paths = set(list_response.paths if list_response else ())
        if get_response is not None:
            listed_paths.update(get_response.present_paths())
        files = dict(get_response.files if get_response else {})
        version = None
        for response in (get_response, list_response):
            if response and response.version is not None:
                version = response.version
                break
        confirmation = ConfirmationLevel.EXACT
        for response in (get_response, list_response):
            if response and response.confirmation_level != ConfirmationLevel.EXACT:
                confirmation = response.confirmation_level

        checks: list[OperationCheck] = []
        insufficient = False
        mismatch = False
        positive_operations = 0
        missing_positive = 0

        for operation in ticket.operations:
            if operation.action == "delete":
                present = operation.path in listed_paths
                if present:
                    mismatch = True
                    checks.append(
                        OperationCheck(
                            operation.path,
                            operation.action,
                            "mismatch",
                            False,
                            "path is still present",
                            path_present=True,
                        )
                    )
                else:
                    checks.append(
                        OperationCheck(
                            operation.path,
                            operation.action,
                            "matched",
                            True,
                            "path is absent",
                            path_present=False,
                        )
                    )
                continue

            positive_operations += 1
            if operation.path not in listed_paths:
                missing_positive += 1
                checks.append(
                    OperationCheck(
                        operation.path,
                        operation.action,
                        "missing",
                        False,
                        "path is absent from authoritative listing",
                        expected_sha256=operation.content_sha256,
                        path_present=False,
                    )
                )
                continue

            observed = files.get(operation.path, _MISSING)
            if observed is None or observed is _MISSING:
                insufficient = True
                checks.append(
                    OperationCheck(
                        operation.path,
                        operation.action,
                        "insufficient",
                        None,
                        "remote confirmed the path but not its contents",
                        expected_sha256=operation.content_sha256,
                        path_present=True,
                    )
                )
                continue

            observed_hash = _sha256_bytes(observed)
            if operation.content_sha256 and observed_hash != operation.content_sha256:
                mismatch = True
                checks.append(
                    OperationCheck(
                        operation.path,
                        operation.action,
                        "mismatch",
                        False,
                        "remote contents do not match approved operations",
                        expected_sha256=operation.content_sha256,
                        observed_sha256=observed_hash,
                        path_present=True,
                    )
                )
            else:
                checks.append(
                    OperationCheck(
                        operation.path,
                        operation.action,
                        "matched",
                        True,
                        "remote contents match",
                        expected_sha256=operation.content_sha256,
                        observed_sha256=observed_hash,
                        path_present=True,
                    )
                )

        if insufficient or confirmation != ConfirmationLevel.EXACT:
            return ReconciliationReport(
                status=PublicationStatus.UNCONFIRMED,
                confirmation=ConfirmationLevel.INSUFFICIENT,
                ticket=ticket,
                checks=tuple(checks),
                observed_version=version,
                reason="remote confirmation does not prove the approved operations",
                next_action="obtain_stronger_remote_confirmation",
                safe_to_continue=False,
                requires_manual_confirmation=True,
            )
        if mismatch:
            return ReconciliationReport(
                status=PublicationStatus.UNCONFIRMED,
                confirmation=ConfirmationLevel.EXACT,
                ticket=ticket,
                checks=tuple(checks),
                observed_version=version,
                reason="remote state differs from the approved publication",
                next_action="manual_confirmation_before_any_write",
                safe_to_continue=False,
                requires_manual_confirmation=True,
            )
        if positive_operations and missing_positive == positive_operations:
            return ReconciliationReport(
                status=PublicationStatus.NOT_PUBLISHED,
                confirmation=ConfirmationLevel.EXACT,
                ticket=ticket,
                checks=tuple(checks),
                observed_version=version,
                reason="none of the additive operations are present",
                next_action="republish_using_same_ticket_and_scope",
                safe_to_continue=False,
                safe_to_retry=True,
                requires_manual_confirmation=False,
            )
        if missing_positive:
            return ReconciliationReport(
                status=PublicationStatus.UNCONFIRMED,
                confirmation=ConfirmationLevel.EXACT,
                ticket=ticket,
                checks=tuple(checks),
                observed_version=version,
                reason="only part of the approved publication is present",
                next_action="manual_confirmation_before_any_write",
                safe_to_continue=False,
                requires_manual_confirmation=True,
            )
        return ReconciliationReport(
            status=PublicationStatus.CONFIRMED,
            confirmation=ConfirmationLevel.EXACT,
            ticket=ticket,
            checks=tuple(checks),
            observed_version=version,
            reason="remote files match the approved operations",
            next_action="continue_without_resending_write",
            safe_to_continue=True,
            safe_to_retry=False,
            requires_manual_confirmation=False,
        )


class GuardedHubClient(_BaseGuardedHubClient):
    """Synchronous capability-bound Hub client using a local or remote transport."""

    def _send(self, request: HubRequest) -> HubResponse:
        sender = getattr(self.transport, "send_sync", None) or self.transport.send
        response = sender(request)
        if inspect.isawaitable(response):
            raise RuntimeError(
                "sync GuardedHubClient received an awaitable transport; use AsyncGuardedHubClient"
            )
        if isinstance(response, HubResponse):
            response.request = request
        return response

    def list_files(self, store_id: str, *, correlation_id: str | None = None, **_: Any) -> HubResponse:
        request = self._build_request(
            HubAction.LIST_FILES.value, store_id, correlation_id=correlation_id
        )
        return self._send(request)

    def get_files(
        self,
        store_id: str,
        file_paths: Iterable[str],
        *,
        correlation_id: str | None = None,
    ) -> HubResponse:
        request = self._build_request(
            HubAction.GET_FILES.value,
            store_id,
            paths=tuple(file_paths),
            correlation_id=correlation_id,
        )
        return self._send(request)

    read = get_files

    def replace_files(
        self,
        store_id: str,
        message: str,
        contents: bytes | Iterable[Any],
        *,
        expected_version: int | None = None,
        version_must_equal: int | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> HubResponse:
        operations = replace_operation_specs(contents)
        key = idempotency_key or self._idempotency_key(
            store_id, HubAction.REPLACE_FILES.value, operations
        )
        request = self._build_request(
            HubAction.REPLACE_FILES.value,
            store_id,
            operations=operations,
            message=message,
            expected_version=expected_version or version_must_equal,
            idempotency_key=key,
            correlation_id=correlation_id,
        )
        return self._send(request)

    def modify_files(
        self,
        store_id: str,
        message: str,
        file_ops: Any,
        *,
        expected_version: int | None = None,
        version_must_equal: int | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> HubResponse:
        operations = operation_specs_from_file_ops(file_ops)
        key = idempotency_key or self._idempotency_key(
            store_id, HubAction.MODIFY_FILES.value, operations
        )
        request = self._build_request(
            HubAction.MODIFY_FILES.value,
            store_id,
            operations=operations,
            message=message,
            expected_version=expected_version or version_must_equal,
            idempotency_key=key,
            correlation_id=correlation_id,
        )
        return self._send(request)

    write = modify_files
    publish = modify_files

    def publish_modification(self, *args: Any, **kwargs: Any) -> PublicationResult:
        try:
            response = self.modify_files(*args, **kwargs)
            return PublicationResult(
                status=PublicationStatus.CONFIRMED, response=response
            )
        except WriteOutcomeUnknownError as exc:
            return PublicationResult(
                status=PublicationStatus.UNCONFIRMED,
                receipt=exc.receipt,
                error=exc,
            )

    def reconcile(
        self,
        error_or_ticket: RecoveryTicket | BaseException,
        *,
        credential_ref: str | None = None,
    ) -> ReconciliationReport:
        ticket = self._ticket_from(error_or_ticket)
        list_request = self._build_recovery_request(
            ticket,
            HubAction.LIST_FILES.value,
            credential_ref=credential_ref,
        )
        get_request = self._build_recovery_request(
            ticket,
            HubAction.GET_FILES.value,
            paths=ticket.paths,
            credential_ref=credential_ref,
        )
        try:
            list_response = self._send(list_request)
            get_response = self._send(get_request)
            error = None
        except Exception as exc:  # verification must report an unconfirmed state
            if isinstance(exc, CapabilityDeniedError):
                raise
            return self._evaluate_responses(ticket, None, None, exc)
        return self._evaluate_responses(ticket, list_response, get_response, error)

    recover = reconcile
    verify_publication = reconcile


class AsyncGuardedHubClient(_BaseGuardedHubClient):
    """Async capability-bound Hub client for concurrent read/publish workflows."""

    async def _send(self, request: HubRequest) -> HubResponse:
        sender = getattr(self.transport, "asend", None)
        if sender is None:
            sender = self.transport.send
        response = sender(request)
        if inspect.isawaitable(response):
            response = await response
        if isinstance(response, HubResponse):
            response.request = request
        return response

    async def list_files(
        self, store_id: str, *, correlation_id: str | None = None, **_: Any
    ) -> HubResponse:
        request = self._build_request(
            HubAction.LIST_FILES.value, store_id, correlation_id=correlation_id
        )
        return await self._send(request)

    async def get_files(
        self,
        store_id: str,
        file_paths: Iterable[str],
        *,
        correlation_id: str | None = None,
    ) -> HubResponse:
        request = self._build_request(
            HubAction.GET_FILES.value,
            store_id,
            paths=tuple(file_paths),
            correlation_id=correlation_id,
        )
        return await self._send(request)

    read = get_files

    async def replace_files(
        self,
        store_id: str,
        message: str,
        contents: bytes | Iterable[Any],
        *,
        expected_version: int | None = None,
        version_must_equal: int | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> HubResponse:
        operations = replace_operation_specs(contents)
        key = idempotency_key or self._idempotency_key(
            store_id, HubAction.REPLACE_FILES.value, operations
        )
        request = self._build_request(
            HubAction.REPLACE_FILES.value,
            store_id,
            operations=operations,
            message=message,
            expected_version=expected_version or version_must_equal,
            idempotency_key=key,
            correlation_id=correlation_id,
        )
        return await self._send(request)

    async def modify_files(
        self,
        store_id: str,
        message: str,
        file_ops: Any,
        *,
        expected_version: int | None = None,
        version_must_equal: int | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> HubResponse:
        operations = operation_specs_from_file_ops(file_ops)
        key = idempotency_key or self._idempotency_key(
            store_id, HubAction.MODIFY_FILES.value, operations
        )
        request = self._build_request(
            HubAction.MODIFY_FILES.value,
            store_id,
            operations=operations,
            message=message,
            expected_version=expected_version or version_must_equal,
            idempotency_key=key,
            correlation_id=correlation_id,
        )
        return await self._send(request)

    write = modify_files
    publish = modify_files

    async def publish_modification(
        self, *args: Any, **kwargs: Any
    ) -> PublicationResult:
        try:
            response = await self.modify_files(*args, **kwargs)
            return PublicationResult(
                status=PublicationStatus.CONFIRMED, response=response
            )
        except WriteOutcomeUnknownError as exc:
            return PublicationResult(
                status=PublicationStatus.UNCONFIRMED,
                receipt=exc.receipt,
                error=exc,
            )

    async def reconcile(
        self,
        error_or_ticket: RecoveryTicket | BaseException,
        *,
        credential_ref: str | None = None,
    ) -> ReconciliationReport:
        ticket = self._ticket_from(error_or_ticket)
        list_request = self._build_recovery_request(
            ticket,
            HubAction.LIST_FILES.value,
            credential_ref=credential_ref,
        )
        get_request = self._build_recovery_request(
            ticket,
            HubAction.GET_FILES.value,
            paths=ticket.paths,
            credential_ref=credential_ref,
        )
        try:
            list_response = await self._send(list_request)
            get_response = await self._send(get_request)
        except Exception as exc:
            if isinstance(exc, CapabilityDeniedError):
                raise
            return self._evaluate_responses(ticket, None, None, exc)
        return self._evaluate_responses(ticket, list_response, get_response)

    async def recover(
        self, error_or_ticket: RecoveryTicket | BaseException, **kwargs: Any
    ) -> ReconciliationReport:
        return await self.reconcile(error_or_ticket, **kwargs)

    async def verify_publication(
        self, error_or_ticket: RecoveryTicket | BaseException, **kwargs: Any
    ) -> ReconciliationReport:
        return await self.reconcile(error_or_ticket, **kwargs)


# Common descriptive aliases used by integrations and exploratory callers.
ScopedHubClient = GuardedHubClient
AsyncScopedHubClient = AsyncGuardedHubClient
CapabilityBoundHubClient = GuardedHubClient
AsyncCapabilityBoundHubClient = AsyncGuardedHubClient
AuthorizedHubClient = GuardedHubClient
AsyncAuthorizedHubClient = AsyncGuardedHubClient
LocalHub = LocalHubTransport
RecordingHubTransport = LocalHubTransport
InMemoryHubTransport = LocalHubTransport
FakeHubTransport = LocalHubTransport
HubScope = HubCapability
HubPermission = HubCapability
CapabilityGrant = HubCapability
CapabilityConstraint = HubCapability
StoreCapability = HubCapability
Capability = HubCapability
RefreshableCredentials = CredentialSource
RefreshingCredentials = CredentialSource
CredentialRef = str
Approval = ApprovalProof
ApprovalToken = ApprovalProof
ApprovalCertificate = ApprovalProof
ApprovalAttestation = ApprovalProof
Proof = ApprovalProof
HubReceipt = RecoveryTicket
WriteReceipt = RecoveryTicket
UnconfirmedWrite = PublicationResult
UnknownWriteOutcome = PublicationResult
Reconciliation = ReconciliationReport
ReconciliationResult = ReconciliationReport
VerificationReport = ReconciliationReport
UnconfirmedWriteError = UnconfirmedPublicationError
UnknownWriteOutcomeError = WriteOutcomeUnknownError
