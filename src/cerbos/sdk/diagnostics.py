# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Shareable, application-scoped diagnostics for authorization checks.

The module never changes an authorization response.  It builds a separate
support view whose public fields are chosen by the application.  Private
attribute values can additionally be supplied as secrets and are scrubbed from
strings before the view is serialized or logged.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, fields as dataclass_fields
from enum import Enum
from typing import Any

REDACTED = "[REDACTED]"
DIAGNOSTIC_SCHEMA_VERSION = "cerbos.diagnostics/v1"

# Operational fields which are useful in a support ticket and do not contain
# request attributes.  Applications can replace this set via ``PublicScope``.
DEFAULT_PUBLIC_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "correlation_id",
        "request_id",
        "cerbos_call_id",
        "status",
        "completeness",
        "partial",
        "failed",
        "empty",
        "summary",
        "items.action",
        "items.resource_id",
        "items.resource_kind",
        "items.status",
        "items.outcome",
        "items.missing",
        "items.denied",
        "items.decision",
        "items.effect",
        "items.effect_name",
        "items.allowed",
        "items.found",
        "items.resource_found",
        "items.result_present",
        "items.has_decision",
        "items.policy",
        "items.matched_policy",
        "items.matched_scope",
        "items.scope",
        "items.policy_version",
        "items.version",
        "items.requested_policy_version",
        "items.principal_policy_version",
        "items.correlation_id",
        "items.request_id",
        "items.cerbos_call_id",
        "items.validation_error_count",
        "items.output_error_count",
        "items.failed",
        "items.error",
        "items.error.type",
        "items.error.code",
        "error",
        "error.type",
        "error.code",
    }
)


class RequestDiagnosticStatus(str, Enum):
    """Completeness of the whole checked request."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class DiagnosticStatus(str, Enum):
    """Diagnostic state for one requested action."""

    ALLOWED = "allowed"
    DENIED = "denied"
    ERROR = "error"
    FAILED = "failed"
    MISSING = "missing"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PublicScope:
    """Application-defined shareable scope.

    ``allowed_fields`` uses dotted paths.  Short leaf names such as
    ``action`` or ``correlation_id`` are also accepted.  Set it to ``None`` or
    ``"all"`` only when the complete diagnostic object is safe to share.
    """

    allowed_fields: Iterable[str] | str | None = field(
        default_factory=lambda: set(DEFAULT_PUBLIC_FIELDS)
    )
    public_attributes: Mapping[str, Iterable[str]] | Iterable[str] = field(
        default_factory=frozenset
    )
    secret_values: Iterable[Any] = field(default_factory=tuple)
    secret_patterns: Iterable[str | re.Pattern[str]] = field(default_factory=tuple)
    replacement: str = REDACTED
    expose_error_messages: bool = False
    field_filter: Callable[[str, str, Any], bool] | None = None
    report_mapper: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.allowed_fields, str):
            if self.allowed_fields != "all":
                raise ValueError("allowed_fields string must be 'all'")
            allowed = None
        elif self.allowed_fields is None:
            allowed = None
        else:
            allowed = frozenset(self.allowed_fields)
        object.__setattr__(self, "allowed_fields", allowed)

        if isinstance(self.public_attributes, Mapping):
            attrs = {
                key: frozenset(values) for key, values in self.public_attributes.items()
            }
        else:
            attrs = {"*": frozenset(self.public_attributes)}
        object.__setattr__(self, "public_attributes", attrs)
        object.__setattr__(
            self, "secret_values", tuple(value for value in self.secret_values if value)
        )
        object.__setattr__(self, "secret_patterns", tuple(self.secret_patterns))


@dataclass
class DiagnosticError:
    type: str | None = None
    code: str | int | None = None
    message: str | None = None

    def to_dict(self, *, include_message: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {"type": self.type, "code": self.code}
        if include_message:
            result["message"] = self.message
        return {key: value for key, value in result.items() if value is not None}


@dataclass
class DiagnosticEntry:
    action: str | None
    status: str
    correlation_id: str | None = None
    policy_version: str | None = None
    matched_policy: str | None = None
    resource_id: str | None = None
    resource_kind: str | None = None
    matched_scope: str | None = None
    requested_policy_version: str | None = None
    principal_policy_version: str | None = None
    request_id: str | None = None
    cerbos_call_id: str | None = None
    decision: str | None = None
    effect: str | int | None = None
    effect_name: str | None = None
    allowed: bool | None = None
    found: bool = False
    resource_found: bool = False
    result_present: bool = False
    has_decision: bool = False
    failed: bool = False
    error: DiagnosticError | None = None
    validation_error_count: int = 0
    output_error_count: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str | None:
        return self.policy_version

    @property
    def policy(self) -> str | None:
        return self.matched_policy

    @property
    def outcome(self) -> str:
        return self.status

    @property
    def missing(self) -> bool:
        return self.status == DiagnosticStatus.MISSING.value

    @property
    def denied(self) -> bool:
        return self.decision == "deny"

    @property
    def scope(self) -> str | None:
        return self.matched_scope

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["version"] = self.policy_version
        data["policy"] = self.matched_policy
        data["outcome"] = self.status
        data["scope"] = self.matched_scope
        data["missing"] = self.status == DiagnosticStatus.MISSING.value
        data["denied"] = self.decision == "deny"
        if self.error is not None:
            data["error"] = self.error.to_dict(include_message=True)
        return data


@dataclass
class DiagnosticReport:
    correlation_id: str | None = None
    request_id: str | None = None
    cerbos_call_id: str | None = None
    status: str = RequestDiagnosticStatus.COMPLETE.value
    entries: list[DiagnosticEntry] = field(default_factory=list)
    error: DiagnosticError | None = None
    schema_version: str = DIAGNOSTIC_SCHEMA_VERSION
    empty: bool = False
    summary: dict[str, int] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status == RequestDiagnosticStatus.FAILED.value

    @property
    def partial(self) -> bool:
        return self.status == RequestDiagnosticStatus.PARTIAL.value

    @property
    def complete(self) -> bool:
        return self.status == RequestDiagnosticStatus.COMPLETE.value

    @property
    def items(self) -> list[DiagnosticEntry]:
        return self.entries

    @property
    def results(self) -> list[DiagnosticEntry]:
        return self.entries

    @property
    def diagnostics(self) -> list[DiagnosticEntry]:
        return self.entries

    @property
    def actions(self) -> list[str | None]:
        return [entry.action for entry in self.entries]

    def to_dict(self) -> dict[str, Any]:
        items = [entry.to_dict() for entry in self.entries]
        result = {
            "schema_version": self.schema_version,
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "cerbos_call_id": self.cerbos_call_id,
            "status": self.status,
            "completeness": self.status,
            "partial": self.partial,
            "failed": self.failed,
            "complete": self.complete,
            "empty": self.empty,
            "summary": dict(self.summary),
            "items": items,
            # Compatibility aliases for callers describing the same item set.
            "entries": items,
            "results": items,
        }
        if self.error is not None:
            result["error"] = self.error.to_dict(include_message=True)
        return result

    def to_json(self, *, indent: int | None = 2, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str, **kwargs)

    def public_view(
        self,
        scope: PublicScope
        | Mapping[str, Any]
        | Iterable[str]
        | Callable[..., Any]
        | None = None,
        *,
        allowed_fields: Iterable[str] | str | None = None,
        secret_values: Iterable[Any] | None = None,
        secret_patterns: Iterable[str | re.Pattern[str]] | None = None,
        public_attributes: Mapping[str, Iterable[str]] | Iterable[str] | None = None,
        replacement: str = REDACTED,
        expose_error_messages: bool | None = None,
        field_filter: Callable[[str, str, Any], bool] | None = None,
    ) -> "PublicDiagnosticView":
        if isinstance(scope, PublicScope):
            policy = scope
        elif isinstance(scope, Mapping) and any(
            key in {f.name for f in dataclass_fields(PublicScope)} for key in scope
        ):
            valid_keys = {f.name for f in dataclass_fields(PublicScope)}
            options = {key: value for key, value in scope.items() if key in valid_keys}
            policy = PublicScope(**options)
        else:
            if allowed_fields is None and not callable(scope):
                allowed_fields = (
                    scope if scope is not None else set(DEFAULT_PUBLIC_FIELDS)
                )
            mapper = scope if callable(scope) else None
            policy = PublicScope(
                allowed_fields=allowed_fields,
                secret_values=secret_values or (),
                secret_patterns=secret_patterns or (),
                public_attributes=public_attributes or frozenset(),
                replacement=replacement,
                expose_error_messages=bool(expose_error_messages),
                field_filter=field_filter,
                report_mapper=mapper
                if isinstance(mapper, PublicScope) is False
                else None,
            )

        full = self.to_dict()
        _apply_public_attributes(full, self, policy)
        if policy.report_mapper is not None:
            mapped = policy.report_mapper(full)
            if not isinstance(mapped, Mapping):
                raise TypeError("diagnostic report mapper must return a mapping")
            projected: Any = dict(mapped)
        elif policy.allowed_fields is None:
            projected = full
        else:
            projected = _project_fields(
                full, policy.allowed_fields, policy.field_filter
            )

        report_secrets = getattr(self, "_secret_values", ())
        redactor = Redactor(
            (*report_secrets, *policy.secret_values),
            replacement=policy.replacement,
            secret_patterns=(
                *policy.secret_patterns,
                *(secret_patterns or ()),
            ),
        )
        projected = redactor.scrub(projected)

        if not policy.expose_error_messages:
            _remove_error_messages(projected)

        view = PublicDiagnosticView(_to_attr_data(projected))
        view._source_report = self
        view._scope = policy
        return view

    # Common alias used by support workflows.
    def shareable(self, *args: Any, **kwargs: Any) -> "PublicDiagnosticView":
        return self.public_view(*args, **kwargs)

    def log(
        self,
        logger: logging.Logger | None = None,
        *,
        level: int = logging.INFO,
        scope: PublicScope | None = None,
        **kwargs: Any,
    ) -> "PublicDiagnosticView":
        view = self.public_view(scope, **kwargs)
        (logger or logging.getLogger("cerbos.diagnostics")).log(
            level, view.to_json(sort_keys=True)
        )
        return view


class AttrDict(dict):
    """Dictionary with attribute access used by public diagnostic payloads."""

    def __getattr__(self, name: str) -> Any:
        try:
            value = self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        if isinstance(value, dict) and not isinstance(value, AttrDict):
            return _to_attr_data(value)
        if isinstance(value, list):
            return [
                _to_attr_data(item) if isinstance(item, dict) else item
                for item in value
            ]
        return value


class PublicDiagnosticView(AttrDict):
    _source_report: DiagnosticReport | None = None
    _scope: PublicScope | None = None

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_public_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def to_shareable_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def to_json(self, *, indent: int | None = 2, **kwargs: Any) -> str:
        return json.dumps(self._plain(), indent=indent, default=str, **kwargs)

    def _plain(self) -> Any:
        return _to_plain(self)

    @property
    def entries(self) -> list[AttrDict]:
        return list(self.get("items", self.get("entries", self.get("results", []))))

    @property
    def results(self) -> list[AttrDict]:
        return self.entries

    @property
    def action_results(self) -> list[AttrDict]:
        return self.entries

    def log(
        self, logger: logging.Logger | None = None, *, level: int = logging.INFO
    ) -> "PublicDiagnosticView":
        (logger or logging.getLogger("cerbos.diagnostics")).log(
            level, self.to_json(sort_keys=True)
        )
        return self


# Descriptive aliases for callers naming the concept directly.
ShareableDiagnosticView = PublicDiagnosticView
DiagnosticView = PublicDiagnosticView
PublicReport = PublicDiagnosticView
ShareableDiagnosticReport = DiagnosticReport
PublicDiagnosticReport = DiagnosticReport


class Redactor:
    """Scrub known secret values from strings and nested JSON data."""

    def __init__(
        self,
        secret_values: Iterable[Any] = (),
        *,
        replacement: str = REDACTED,
        secret_patterns: Iterable[str | re.Pattern[str]] = (),
    ):
        secrets = {
            str(value) for value in secret_values if isinstance(value, str) and value
        }
        self._patterns = [
            (re.compile(re.escape(value)), replacement)
            for value in sorted(secrets, key=len, reverse=True)
        ]
        for pattern in secret_patterns:
            compiled = pattern if hasattr(pattern, "sub") else re.compile(pattern)
            self._patterns.append((compiled, replacement))
        self.replacement = replacement

    def scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            result = value
            for pattern, replacement in self._patterns:
                result = pattern.sub(replacement, result)
            return result
        if isinstance(value, Mapping):
            return {key: self.scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self.scrub(item) for item in value]
        return value


class SecretRedactionFilter(logging.Filter):
    """Logging filter which scrubs configured values from formatted records."""

    def __init__(
        self,
        secret_values: Iterable[Any] = (),
        *,
        replacement: str = REDACTED,
        secret_patterns: Iterable[str | re.Pattern[str]] = (),
    ):
        super().__init__()
        self.redactor = Redactor(
            secret_values,
            replacement=replacement,
            secret_patterns=secret_patterns,
        )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - logging must never break a request
            message = str(record.msg)
        record.msg = self.redactor.scrub(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = self.redactor.scrub(record.exc_text)
        return True


def log_diagnostics(
    payload: DiagnosticReport | PublicDiagnosticView | Mapping[str, Any],
    logger: logging.Logger | None = None,
    *,
    level: int = logging.INFO,
    scope: PublicScope
    | Mapping[str, Any]
    | Iterable[str]
    | Callable[..., Any]
    | None = None,
    **kwargs: Any,
) -> PublicDiagnosticView:
    if isinstance(payload, DiagnosticReport):
        view = payload.public_view(scope, **kwargs)
    elif isinstance(payload, PublicDiagnosticView):
        view = payload
    else:
        view = PublicDiagnosticView(dict(payload))
    view.log(logger, level=level)
    return view


def diagnostic_view(
    response: Any = None,
    request: Any = None,
    public_scope: PublicScope
    | Mapping[str, Any]
    | Iterable[str]
    | Callable[..., Any]
    | None = None,
    *,
    principal: Any = None,
    resources: Any = None,
    error: BaseException | None = None,
    correlation_id: str | None = None,
    correlation_ids: Mapping[Any, str] | None = None,
    item_errors: Mapping[Any, Any] | None = None,
    scope: PublicScope
    | Mapping[str, Any]
    | Iterable[str]
    | Callable[..., Any]
    | None = None,
    **public_kwargs: Any,
) -> PublicDiagnosticView:
    """Build the application-scoped shareable view in one call."""

    report = build_diagnostic_report(
        response,
        request=request,
        principal=principal,
        resources=resources,
        error=error,
        correlation_id=correlation_id,
        correlation_ids=correlation_ids,
        item_errors=item_errors,
    )
    return report.public_view(
        public_scope if public_scope is not None else scope, **public_kwargs
    )


# Descriptive aliases for integrations using support/public-report vocabulary.
shareable_diagnostics = diagnostic_view
public_diagnostic_view = diagnostic_view
make_public_report = diagnostic_view
to_diagnostics = diagnostic_view


def build_diagnostic_report(
    response: Any = None,
    request: Any = None,
    *,
    principal: Any = None,
    resources: Any = None,
    error: BaseException | None = None,
    correlation_id: str | None = None,
    correlation_ids: Mapping[Any, str] | None = None,
    item_errors: Mapping[Any, Any] | None = None,
    secret_values: Iterable[Any] | None = None,
    collect_request_secrets: bool = True,
) -> DiagnosticReport:
    """Build a transport-independent diagnostic report.

    ``response`` may be an HTTP SDK dataclass, an HTTP JSON mapping, or a
    generated gRPC ``CheckResourcesResponse``.  ``request`` may likewise be an
    HTTP/gRPC request or an SDK ``ResourceList``.
    """

    if request is None and response is not None:
        request = getattr(response, "_sdk_diagnostic_request", None)

    request_id = _first_non_empty(
        _field(request, "request_id"),
        _field(response, "request_id"),
        _mapping_get(correlation_ids, "__request__") if correlation_ids else None,
    )
    effective_correlation_id = _first_non_empty(
        correlation_id,
        _mapping_get(correlation_ids, "__correlation__") if correlation_ids else None,
        _correlation_from_context(request),
        request_id,
    )

    cerbos_call_id = _first_non_empty(
        _field(response, "cerbos_call_id"),
        _trailing_metadata(error, "cerbos-call-id"),
        _trailing_metadata(error, "cerbos_call_id"),
    )

    request_error = _build_error(response=response, error=error)
    request_failed = request_error is not None and _is_request_failure(
        response, request_error
    )

    principal_obj = principal if principal is not None else _field(request, "principal")
    principal_version = _first_non_empty(
        _field(principal_obj, "policy_version"), _field(principal_obj, "policyVersion")
    )

    requested = list(_iter_requested_items(request=request, resources=resources))
    if not requested and response is not None and not request_failed:
        requested = list(_iter_response_actions(response))

    entries: list[DiagnosticEntry] = []
    if request_failed:
        for item in requested or [_RequestedItem(None)]:
            entries.append(
                DiagnosticEntry(
                    action=item.action,
                    status=DiagnosticStatus.FAILED.value,
                    correlation_id=_correlation_for(
                        item, effective_correlation_id, correlation_ids
                    ),
                    policy_version=item.policy_version,
                    requested_policy_version=item.policy_version,
                    principal_policy_version=principal_version,
                    resource_id=item.resource_id,
                    resource_kind=item.resource_kind,
                    request_id=request_id,
                    cerbos_call_id=cerbos_call_id,
                    found=False,
                    result_present=False,
                    has_decision=False,
                    failed=True,
                    error=request_error,
                )
            )
        status = RequestDiagnosticStatus.FAILED.value
    else:
        result_index = _index_results(response)
        for item in requested:
            entries.append(
                _build_entry(
                    item,
                    response=response,
                    result_index=result_index,
                    default_correlation_id=effective_correlation_id,
                    request_id=request_id,
                    cerbos_call_id=cerbos_call_id,
                    principal_version=principal_version,
                    correlation_ids=correlation_ids,
                    item_errors=item_errors,
                )
            )

        unresolved = sum(
            entry.status
            in {
                DiagnosticStatus.ERROR.value,
                DiagnosticStatus.MISSING.value,
                DiagnosticStatus.FAILED.value,
                DiagnosticStatus.UNKNOWN.value,
                DiagnosticStatus.NO_MATCH.value,
            }
            or entry.failed
            for entry in entries
        )
        if not entries:
            status = RequestDiagnosticStatus.COMPLETE.value
        elif unresolved == 0:
            status = RequestDiagnosticStatus.COMPLETE.value
        elif unresolved < len(entries):
            status = RequestDiagnosticStatus.PARTIAL.value
        else:
            status = RequestDiagnosticStatus.FAILED.value

    counts = {
        "total": len(entries),
        "allowed": sum(e.status == DiagnosticStatus.ALLOWED.value for e in entries),
        "denied": sum(e.status == DiagnosticStatus.DENIED.value for e in entries),
        "errors": sum(
            e.status in {DiagnosticStatus.ERROR.value, DiagnosticStatus.FAILED.value}
            or e.failed
            for e in entries
        ),
        "missing": sum(e.status == DiagnosticStatus.MISSING.value for e in entries),
    }

    report = DiagnosticReport(
        correlation_id=effective_correlation_id,
        request_id=request_id,
        cerbos_call_id=cerbos_call_id or None,
        status=status,
        entries=entries,
        error=request_error if request_failed else None,
        empty=not entries,
        summary=counts,
    )
    request_secrets = (
        _collect_request_secret_values(request, principal_obj, resources)
        if collect_request_secrets
        else []
    )
    principal_attrs, resource_attrs = _attribute_context(
        request, principal_obj, resources
    )
    report._principal_attributes = principal_attrs
    report._resource_attributes = resource_attrs
    report._secret_values = tuple(
        dict.fromkeys(
            str(value)
            for value in [*request_secrets, *(secret_values or ())]
            if value is not None and str(value)
        )
    )
    return report


@dataclass(frozen=True)
class _RequestedItem:
    action: str | None
    resource_id: str | None = None
    resource_kind: str | None = None
    policy_version: str | None = None
    scope: str | None = None
    correlation_id: str | None = None


def _build_entry(
    item: _RequestedItem,
    *,
    response: Any,
    result_index: dict[str, Any],
    default_correlation_id: str | None,
    request_id: str | None,
    cerbos_call_id: str | None,
    principal_version: str | None,
    correlation_ids: Mapping[Any, str] | None,
    item_errors: Mapping[Any, Any] | None,
) -> DiagnosticEntry:
    result = _find_result(result_index, item)
    resource = _field(result, "resource") if result is not None else None
    actions = _field(result, "actions") if result is not None else None
    action_present = False
    effect_value = None
    if actions is not None and item.action is not None:
        action_present, effect_value = _mapping_contains(actions, item.action)

    effect_name, decision, allowed = _decode_effect(effect_value)
    meta = _field(result, "meta") if result is not None else None
    meta_actions = _field(meta, "actions") if meta is not None else None
    action_meta = None
    if meta_actions is not None and item.action is not None:
        _, action_meta = _mapping_contains(meta_actions, item.action)

    matched_policy = _first_non_empty(
        _field(action_meta, "matched_policy"), _field(action_meta, "matchedPolicy")
    )
    matched_scope = _first_non_empty(
        _field(action_meta, "matched_scope"), _field(action_meta, "matchedScope")
    )
    observed_version = _first_non_empty(
        _field(resource, "policy_version"), _field(resource, "policyVersion")
    )
    resource_id = _first_non_empty(_field(resource, "id"), item.resource_id)
    resource_kind = _first_non_empty(_field(resource, "kind"), item.resource_kind)
    scope = _first_non_empty(_field(resource, "scope"), item.scope)

    output_errors = _output_errors(result, item.action)
    explicit_error = _mapping_get(item_errors, (resource_id, item.action))
    if explicit_error is None:
        explicit_error = _mapping_get(item_errors, item.action)
    if explicit_error is None and item.action is not None:
        explicit_error = _mapping_get(item_errors, str(item.action))

    error: DiagnosticError | None = None
    if explicit_error is not None:
        error = _coerce_item_error(explicit_error)
    elif output_errors:
        error = DiagnosticError(
            type="OutputEvaluationError",
            code="OUTPUT_ERROR",
            message="; ".join(output_errors),
        )

    validation_errors = _field(result, "validation_errors") or _field(
        result, "validationErrors"
    )
    validation_count = _len(validation_errors)

    resource_found = result is not None
    found = action_present
    result_present = action_present
    has_decision = decision in {"allow", "deny"}

    if error is not None:
        status = DiagnosticStatus.ERROR.value
        failed = True
    elif not found or not action_present:
        status = DiagnosticStatus.MISSING.value
        failed = False
    elif decision == "allow":
        status = DiagnosticStatus.ALLOWED.value
        failed = False
    elif decision == "deny":
        status = DiagnosticStatus.DENIED.value
        failed = False
    elif decision == "no_match":
        status = DiagnosticStatus.NO_MATCH.value
        failed = False
    else:
        status = DiagnosticStatus.UNKNOWN.value
        failed = False

    return DiagnosticEntry(
        action=item.action,
        status=status,
        correlation_id=_correlation_for(item, default_correlation_id, correlation_ids),
        policy_version=_first_non_empty(observed_version, item.policy_version),
        matched_policy=matched_policy or None,
        resource_id=resource_id,
        resource_kind=resource_kind,
        matched_scope=matched_scope or scope,
        requested_policy_version=item.policy_version,
        principal_policy_version=principal_version,
        request_id=request_id,
        cerbos_call_id=cerbos_call_id,
        decision=decision,
        effect=effect_value if isinstance(effect_value, (str, int)) else None,
        effect_name=effect_name,
        allowed=allowed,
        found=found,
        resource_found=resource_found,
        result_present=result_present,
        has_decision=has_decision,
        failed=failed,
        error=error,
        validation_error_count=validation_count,
        output_error_count=len(output_errors),
    )


def _attribute_context(
    request: Any, principal: Any = None, resources: Any = None
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    principal_obj = principal or _field(request, "principal")
    principal_attrs = _native_attrs(_field(principal_obj, "attr"))

    source = resources
    if source is None and request is not None:
        source = _field(request, "resources")
    entries = source
    if not isinstance(source, list) and _field(source, "resources") is not None:
        entries = _field(source, "resources")

    index: dict[str, dict[str, Any]] = {}
    for entry in entries or []:
        resource = _field(entry, "resource")
        resource_id = _field(resource, "id")
        version = _first_non_empty(
            _field(resource, "policy_version"), _field(resource, "policyVersion")
        )
        attrs = _native_attrs(_field(resource, "attr"))
        if resource_id is not None:
            index[f"{resource_id}\0{version or ''}"] = attrs
            index.setdefault(str(resource_id), attrs)
    return principal_attrs, index


def _native_attrs(attrs: Any) -> dict[str, Any]:
    if attrs is None:
        return {}
    if isinstance(attrs, Mapping):
        items = attrs.items()
    elif hasattr(attrs, "keys"):
        items = ((key, attrs[key]) for key in attrs.keys())
    else:
        return {}
    return {str(key): _proto_to_raw(value) for key, value in items}


def _apply_public_attributes(
    full: Mapping[str, Any], report: DiagnosticReport, policy: PublicScope
) -> None:
    allowed = policy.public_attributes
    principal_allowed = set(allowed.get("*", ())) | set(allowed.get("principal", ()))
    resource_allowed = (
        set(allowed.get("*", ()))
        | set(allowed.get("resource", ()))
        | set(allowed.get("resources", ()))
    )

    principal_attrs = getattr(report, "_principal_attributes", {})
    if principal_allowed:
        full["principal_attributes"] = _filter_attributes(
            principal_attrs, principal_allowed
        )

    resource_attrs = getattr(report, "_resource_attributes", {})
    for item in full.get("items", []):
        resource_id = item.get("resource_id")
        version = item.get("policy_version")
        attrs = resource_attrs.get(f"{resource_id}\0{version or ''}")
        if attrs is None:
            attrs = resource_attrs.get(str(resource_id), {})
        selected = _filter_attributes(attrs, resource_allowed)
        if selected:
            item["attributes"] = selected


def _filter_attributes(attrs: Mapping[str, Any], allowed: set[str]) -> dict[str, Any]:
    if "*" in allowed:
        return dict(attrs)
    return {key: value for key, value in attrs.items() if key in allowed}


def _collect_request_secret_values(
    request: Any, principal: Any = None, resources: Any = None
) -> list[Any]:
    values: list[Any] = []
    principal_obj = principal or _field(request, "principal")
    _collect_attr_values(_field(principal_obj, "attr"), values)

    source = resources
    if source is None and request is not None:
        source = _field(request, "resources")
    entries = source
    if not isinstance(source, list) and _field(source, "resources") is not None:
        entries = _field(source, "resources")
    for entry in entries or []:
        resource = _field(entry, "resource")
        _collect_attr_values(_field(resource, "attr"), values)
    return values


_SENSITIVE_ATTRIBUTE_KEY = re.compile(
    r"(private|secret|token|password|passwd|credential|marker|jwt)", re.IGNORECASE
)


def _collect_attr_values(attrs: Any, output: list[Any], path: str = "") -> None:
    if attrs is None:
        return
    for key in _mapping_keys(attrs):
        _, value = _mapping_contains(attrs, key)
        raw = _proto_to_raw(value)
        child_path = f"{path}.{key}" if path else str(key)
        if _SENSITIVE_ATTRIBUTE_KEY.search(str(key)):
            _collect_strings(raw, output)
        elif isinstance(raw, Mapping):
            _collect_attr_values(raw, output, child_path)
        elif isinstance(raw, (list, tuple, set, frozenset)):
            for item in raw:
                if isinstance(item, Mapping):
                    _collect_attr_values(item, output, child_path)


def _proto_to_raw(value: Any) -> Any:
    if hasattr(value, "DESCRIPTOR") and hasattr(value, "ListFields"):
        try:
            from google.protobuf.json_format import MessageToDict

            return MessageToDict(value, preserving_proto_field_name=True)
        except Exception:  # noqa: BLE001
            return str(value)
    return value


def _collect_strings(value: Any, output: list[Any]) -> None:
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, Mapping):
        for item in value.values():
            _collect_strings(item, output)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _collect_strings(item, output)


def _iter_requested_items(
    *, request: Any, resources: Any = None
) -> Iterable[_RequestedItem]:
    source = resources
    if source is None and request is not None:
        source = _field(request, "resources")

    if source is None:
        return []

    # ResourceList and HTTP request both expose .resources, but if we were
    # given the request itself we already selected that field above.
    entries = source
    if not isinstance(source, list) and _field(source, "resources") is not None:
        entries = _field(source, "resources")

    result: list[_RequestedItem] = []
    for entry in entries or []:
        resource = _field(entry, "resource")
        actions = _field(entry, "actions")
        if actions is None:
            actions = _field(entry, "action")
        action_values = _as_iterable(actions)
        for action in action_values:
            result.append(
                _RequestedItem(
                    action=str(action) if action is not None else None,
                    resource_id=_field(resource, "id"),
                    resource_kind=_field(resource, "kind"),
                    policy_version=_first_non_empty(
                        _field(resource, "policy_version"),
                        _field(resource, "policyVersion"),
                    ),
                    scope=_field(resource, "scope"),
                    correlation_id=None,
                )
            )
    return result


def _iter_response_actions(response: Any) -> Iterable[_RequestedItem]:
    results = _field(response, "results") or []
    for result in results:
        resource = _field(result, "resource")
        actions = _field(result, "actions")
        for action in _mapping_keys(actions):
            yield _RequestedItem(
                action=str(action),
                resource_id=_field(resource, "id"),
                resource_kind=_field(resource, "kind"),
                policy_version=_first_non_empty(
                    _field(resource, "policy_version"),
                    _field(resource, "policyVersion"),
                ),
                scope=_field(resource, "scope"),
            )


def _index_results(response: Any) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for result in _field(response, "results") or []:
        resource = _field(result, "resource")
        resource_id = _field(resource, "id")
        version = _first_non_empty(
            _field(resource, "policy_version"), _field(resource, "policyVersion")
        )
        if resource_id is not None:
            index[f"{resource_id}\0{version or ''}"] = result
            index.setdefault(str(resource_id), result)
    return index


def _find_result(index: Mapping[str, Any], item: _RequestedItem) -> Any:
    if item.resource_id is None:
        return next(iter(index.values()), None)
    key = f"{item.resource_id}\0{item.policy_version or ''}"
    if key in index:
        return index[key]
    return index.get(str(item.resource_id))


def _build_error(
    *, response: Any, error: BaseException | None
) -> DiagnosticError | None:
    status_error = _field(response, "status_msg") or _field(response, "statusMsg")
    status_code = _field(response, "status_code") or _field(response, "statusCode")

    if status_error is not None:
        return DiagnosticError(
            type=type(status_error).__name__,
            code=_field(status_error, "code"),
            message=_field(status_error, "message"),
        )

    if error is not None:
        nested_error = _field(error, "error")
        if nested_error is not None:
            return DiagnosticError(
                type=type(error).__name__,
                code=_field(nested_error, "code"),
                message=_field(nested_error, "message") or str(error),
            )
        code = None
        code_fn = getattr(error, "code", None)
        if callable(code_fn):
            try:
                code_value = code_fn()
                code = getattr(code_value, "name", None) or str(code_value)
            except Exception:  # noqa: BLE001
                code = None
        details_fn = getattr(error, "details", None)
        message = None
        if callable(details_fn):
            try:
                message = details_fn()
            except Exception:  # noqa: BLE001
                message = None
        return DiagnosticError(
            type=type(error).__name__,
            code=code,
            message=message or str(error),
        )

    if isinstance(status_code, int) and status_code >= 400:
        return DiagnosticError(type="HTTPError", code=status_code)

    return None


def _is_request_failure(response: Any, error: DiagnosticError) -> bool:
    if response is None:
        return True
    failed_fn = getattr(response, "failed", None)
    if callable(failed_fn):
        try:
            return bool(failed_fn())
        except Exception:  # noqa: BLE001
            pass
    status_code = _field(response, "status_code") or _field(response, "statusCode")
    return isinstance(status_code, int) and status_code >= 400


def _coerce_item_error(value: Any) -> DiagnosticError:
    if isinstance(value, DiagnosticError):
        return value
    if isinstance(value, Mapping):
        return DiagnosticError(
            type=value.get("type"),
            code=value.get("code"),
            message=value.get("message") or value.get("error"),
        )
    return DiagnosticError(
        type="ItemEvaluationError", code="ITEM_ERROR", message=str(value)
    )


def _output_errors(result: Any, action: str | None) -> list[str]:
    outputs = _field(result, "outputs") or []
    errors: list[str] = []
    for output in outputs:
        output_action = _field(output, "action")
        message = _field(output, "error")
        if message and (action is None or output_action == action):
            errors.append(str(message))
    return errors


def _decode_effect(value: Any) -> tuple[str | None, str | None, bool | None]:
    if value is None:
        return None, None, None

    raw_name = getattr(value, "name", None)
    if raw_name is None and isinstance(value, str):
        raw_name = value.rsplit(".", 1)[-1]
    if raw_name:
        name = str(raw_name).removeprefix("EFFECT_")
        lower = name.lower()
        if lower == "allow":
            return f"EFFECT_{name}", "allow", True
        if lower == "deny":
            return f"EFFECT_{name}", "deny", False
        if lower == "no_match":
            return f"EFFECT_{name}", "no_match", False
        return f"EFFECT_{name}", "unknown", False

    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None, "unknown", None

    # cerbos.effect.v1.Effect values: 0 unspecified, 1 allow, 2 deny, 3 no match.
    if numeric == 1:
        return "EFFECT_ALLOW", "allow", True
    if numeric == 2:
        return "EFFECT_DENY", "deny", False
    if numeric == 3:
        return "EFFECT_NO_MATCH", "no_match", False
    return "EFFECT_UNSPECIFIED", "unknown", None


def _correlation_for(
    item: _RequestedItem,
    default: str | None,
    correlation_ids: Mapping[Any, str] | None,
) -> str | None:
    if not correlation_ids:
        return _first_non_empty(item.correlation_id, default)
    return _first_non_empty(
        _mapping_get(correlation_ids, item.action),
        _mapping_get(correlation_ids, (item.resource_id, item.action)),
        item.correlation_id,
        default,
    )


def _project_fields(
    value: Any,
    allowed_fields: frozenset[str] | set[str],
    field_filter: Callable[[str, str, Any], bool] | None = None,
    *,
    path: str = "",
) -> Any:
    if path and _path_allowed(path, allowed_fields):
        return value

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if field_filter is not None and not field_filter(
                child_path, str(key), item
            ):
                continue
            projected = _project_fields(
                item, allowed_fields, field_filter, path=child_path
            )
            if projected is not _OMIT and projected != {} and projected != []:
                result[key] = projected
            elif _path_allowed(child_path, allowed_fields) and not isinstance(
                item, (Mapping, list)
            ):
                result[key] = projected
        return result

    if isinstance(value, list):
        rows = [
            _project_fields(item, allowed_fields, field_filter, path=f"{path}[]")
            for item in value
        ]
        return [row for row in rows if row is not _OMIT and row != {}]

    leaf = path.rsplit(".", 1)[-1].replace("[]", "") if path else ""
    if _path_allowed(path, allowed_fields) or (leaf and leaf in allowed_fields):
        return value
    return _OMIT


_OMIT = object()


def _path_allowed(path: str, allowed_fields: Iterable[str]) -> bool:
    normalized = path.replace("[].", ".").replace("[]", "")
    aliases = {normalized}
    for prefix in ("entries", "results", "diagnostics"):
        if normalized.startswith(f"{prefix}."):
            aliases.add("items." + normalized.split(".", 1)[1])
    if normalized in allowed_fields or path in allowed_fields:
        return True
    if aliases & set(allowed_fields):
        return True
    leaf = normalized.rsplit(".", 1)[-1]
    return leaf in allowed_fields


def _remove_error_messages(value: Any) -> None:
    if isinstance(value, Mapping):
        error = value.get("error")
        if isinstance(error, dict):
            error.pop("message", None)
        for item in value.values():
            _remove_error_messages(item)
    elif isinstance(value, list):
        for item in value:
            _remove_error_messages(item)


def _to_attr_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return AttrDict({key: _to_attr_data(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_to_attr_data(item) for item in value]
    return value


def _to_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _to_plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    return value


def _field(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        return obj.get(name) or obj.get(_snake_to_camel(name))
    value = getattr(obj, name, None)
    if value is not None:
        return value
    camel = _snake_to_camel(name)
    return getattr(obj, camel, None)


def _snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(part.title() for part in parts[1:])


def _mapping_contains(mapping: Any, key: Any) -> tuple[bool, Any]:
    if mapping is None:
        return False, None
    if isinstance(mapping, Mapping):
        if key in mapping:
            return True, mapping[key]
        if str(key) in mapping:
            return True, mapping[str(key)]
        return False, None
    # protobuf map containers support membership and indexing.
    try:
        if key in mapping:
            return True, mapping[key]
    except TypeError:
        pass
    try:
        return True, mapping[key]
    except (KeyError, TypeError):
        return False, None


def _mapping_get(mapping: Any, key: Any) -> Any:
    if mapping is None:
        return None
    if isinstance(mapping, Mapping):
        if key in mapping:
            return mapping[key]
        return mapping.get(str(key))
    try:
        return mapping[key]
    except (KeyError, TypeError, IndexError):
        return None


def _mapping_keys(mapping: Any) -> Iterable[Any]:
    if mapping is None:
        return []
    if isinstance(mapping, Mapping):
        return mapping.keys()
    try:
        return mapping.keys()
    except AttributeError:
        return []


def _as_iterable(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _len(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return 0


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        return value
    return None


def _correlation_from_context(request: Any) -> str | None:
    context = _field(request, "request_context") or _field(request, "requestContext")
    annotations = _field(context, "annotations")
    if annotations is None:
        return None
    for key in ("correlation_id", "correlationId", "x-correlation-id", "trace_id"):
        found, value = _mapping_contains(annotations, key)
        if found:
            raw = _proto_to_raw(value)
            if isinstance(raw, Mapping):
                raw = raw.get("stringValue") or raw.get("string_value")
            if raw is not None:
                return str(raw)
    return None


def _trailing_metadata(error: BaseException | None, key: str) -> str | None:
    if error is None:
        return None
    fn = getattr(error, "trailing_metadata", None)
    if not callable(fn):
        return None
    try:
        metadata = fn() or ()
    except Exception:  # noqa: BLE001
        return None
    for item_key, value in metadata:
        if item_key == key:
            return value
    return None


create_diagnostic_report = build_diagnostic_report
generate_diagnostic_report = build_diagnostic_report
build_public_report = diagnostic_view
shareable_report = diagnostic_view
public_diagnostics = diagnostic_view
shareable_diagnostic_report = diagnostic_view
build_shareable_view = diagnostic_view
shareable_view = diagnostic_view
get_diagnostics = diagnostic_view
