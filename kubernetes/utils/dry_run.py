# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Scoped approvals for Kubernetes server-side dry-run requests.

A release page can preview a write with ``dryRun=All`` and only then decide
whether to ask for the real change.  This module keeps that preview meaning
on the wire.  A :class:`DryRunPermit` binds a request to one resource, one
action, and one exact change.  :class:`DryRunSession` builds and sends the
request under a permit using the real :class:`kubernetes.client.ApiClient`,
so the URL, query parameters, body, and result it reports are the ones the
server actually received.

A successful preview is evidence, never authority.  Two permit kinds exist:

``DryRunPermit.preview(...)``
    Adds exactly one ``dryRun=All`` query value to every attempt.  The
    returned :class:`DryRunExchange` can be used with :meth:`review` to
    compare a proposed follow-up change, but a preview exchange cannot
    create or act as a commit permit.  Errors that occur after a preview
    response cannot be retried with a changed body: the rebuild fails with
    :class:`PermitMismatch` before a second request is sent.

``DryRunPermit.commit(..., approval=CommitApproval.for_preview(...))``
    Requires an approval built from the successful preview.  The approval
    verifies the preview succeeded and that its change still matches; the
    commit permit then forbids ``dryRun`` on the final request and records
    the HTTP verb, path, and logical action the server executed.

Typical flow::

    body = V1ConfigMap(...)
    resource = '/api/v1/namespaces/default/configmaps/sample'

    preview_permit = DryRunPermit.preview(resource, 'replace', body)
    session = DryRunSession(api_client)
    preview = session.send(preview_permit)

    # A reviewer compares preview.body/preview.query_parameters and
    # preview.data.  This is evidence for the decision, not a write.  If
    # the staged body changed, preview.review(body=body) reports it and the
    # approval below is refused until the change is previewed again.
    approval = CommitApproval.for_preview(
        preview, approver='release-manager', reference='CHG-42')
    commit_permit = DryRunPermit.commit(resource, 'replace', body,
                                        approval=approval)
    commit = session.send(commit_permit)
    assert commit.committed
    assert commit.executed_method == 'PUT'

Every permit stores a canonical digest of the resource, action, method,
path, non-``dryRun`` query parameters, and change body.  Rebuilding a
request after parameter construction, a retry, or a caller-side edit can
therefore be checked with :meth:`DryRunPermit.check`.  The resulting
:class:`PermitCheck` names every difference, including a changed body,
changed query parameters, a missing or unexpected ``dryRun`` value, or a
different action.
"""

from dataclasses import dataclass
import copy
from hashlib import sha256
import json
from types import MappingProxyType
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import parse_qsl, urlsplit

from kubernetes.client.api_client import ApiClient
from kubernetes.client.exceptions import ApiException, ApiValueError
from kubernetes.client.rest import RESTResponse  # noqa: F401

__all__ = [
    "CommitApproval",
    "DRY_RUN_ALL",
    "DryRunAttempt",
    "DryRunExchange",
    "DryRunPermit",
    "DryRunRequest",
    "DryRunRetry",
    "DryRunSession",
    "PermitCheck",
    "PermitMismatch",
    "review_preview",
]

DRY_RUN_ALL = "All"
"""The only ``dryRun`` query value Kubernetes defines for writes."""

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ACTION_METHODS = (
    ("replace", "PUT"),
    ("update", "PUT"),
    ("put", "PUT"),
    ("create", "POST"),
    ("post", "POST"),
    ("patch", "PATCH"),
    ("apply", "PATCH"),
    ("delete", "DELETE"),
    ("remove", "DELETE"),
)
_DEFAULT_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_UNSET = object()  # distinguishes "omitted" from an explicit None body


class _Serializer:
    """Serialize values exactly as ``ApiClient`` serializes request bodies.

    ``ApiClient.sanitize_for_serialization`` only reads class attributes and
    recursion through itself, so a bare instance is sufficient.  Sharing the
    serializer matters: a permit snapshot and the actual request body must
    use identical wire rules or the digest comparison would be pointless.
    """

    def __init__(self) -> None:
        self._client = ApiClient.__new__(ApiClient)
        self._client.configuration = None

    def __call__(self, value: Any) -> Any:
        return self._client.sanitize_for_serialization(value)


_serialize = _Serializer()


def _canonical_json(value: Any) -> str:
    """Return a stable JSON rendering for comparison and hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    # Body values normally become JSON-native through _serialize.  This
    # fallback keeps hashing total for bytes and date-like values.
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="surrogateescape")
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        try:
            return isoformat()
        except TypeError:
            pass
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return repr(value)


def _body_digest(body: Any) -> Optional[str]:
    if body is None:
        return None
    return sha256(_canonical_json(body).encode("utf-8")).hexdigest()


def _query_pairs(
    query: Optional[Sequence[Tuple[str, str]]],
) -> List[Tuple[str, str]]:
    return [(str(key), str(value)) for key, value in (query or ())]


def _query_without_dry_run(
    query: Optional[Sequence[Tuple[str, str]]],
) -> List[Tuple[str, str]]:
    return [(key, value) for key, value in _query_pairs(query)
            if key != "dryRun"]


def _query_digest(query: Optional[Sequence[Tuple[str, str]]]) -> str:
    return sha256(
        _canonical_json(_query_without_dry_run(query)).encode("utf-8")
    ).hexdigest()


def _url_parts(url: str) -> Tuple[str, List[Tuple[str, str]]]:
    parts = urlsplit(url)
    return parts.path, parse_qsl(parts.query, keep_blank_values=True)


def _dry_run_values(query: Sequence[Tuple[str, str]]) -> List[str]:
    return [value for key, value in query if key == "dryRun"]


def _method_for(action: str, method: Optional[str]) -> str:
    if method is not None:
        method = method.upper()
    else:
        normalized = action.replace("_", "-").lower()
        # Generated operation ids begin with the verb, for example
        # ``replace_namespaced_config_map`` or ``delete_collection``.
        for prefix, candidate in _ACTION_METHODS:
            if normalized.startswith(prefix):
                method = candidate
                break
    if method not in _WRITE_METHODS:
        raise ValueError(
            "cannot derive a write method from action {!r}; "
            "pass method='PUT', 'POST', 'PATCH', or 'DELETE'".format(action))
    return method


def _canonical_digest(
    *,
    resource: str,
    action: str,
    method: str,
    path: str,
    query: Optional[Sequence[Tuple[str, str]]],
    body_digest: Optional[str],
    dry_run: Optional[str],
) -> str:
    """Hash the parts that define a permit.

    Resource and action are included so a permit for one action can never
    stand in for another action on the same wire path.
    """

    payload = {
        "resource": resource,
        "action": action,
        "method": method,
        "path": path,
        "query": _query_without_dry_run(query),
        "body": body_digest,
        "dryRun": dry_run,
    }
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _change_digest(
    *,
    resource: str,
    action: str,
    method: str,
    path: str,
    query: Optional[Sequence[Tuple[str, str]]],
    body_digest: Optional[str],
) -> str:
    """Hash a change without its preview/commit mode.

    A preview and a commit permit for the same change share this digest, so
    an approval issued for a preview can be matched to the commit even
    though their ``dryRun`` values differ.
    """

    payload = {
        "resource": resource,
        "action": action,
        "method": method,
        "path": path,
        "query": _query_without_dry_run(query),
        "body": body_digest,
    }
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _retry_after_seconds(headers: Mapping[str, str]) -> Optional[float]:
    value = None
    for key, header_value in headers.items():
        if str(key).lower() == "retry-after":
            value = header_value
            break
    if value is None:
        return None
    value = str(value).strip()
    if not value.isdigit():
        return None
    return float(int(value))


def _try_json(text: Optional[str]) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


@dataclass(frozen=True)
class PermitCheck:
    """Whether a built request still conforms, and why it might not."""

    matches: bool
    reasons: Tuple[str, ...] = ()

    def describe(self) -> str:
        """Human-readable summary suitable for logs and refusals."""

        if self.matches:
            return "request matches the permit"
        return "request no longer matches the permit: {}".format(
            "; ".join(self.reasons))


@dataclass(frozen=True)
class CommitApproval:
    """The separate approval that can request a real write.

    A preview result cannot create this object by itself; application code
    creates one after the approval decision with :meth:`for_preview`, which
    verifies that the preview succeeded and that the requested change still
    matches what was previewed.  The approval records the change digest, so
    a later edit of the staged body is detected when the commit permit is
    built rather than silently written.
    """

    approver: str
    reference: str
    change_digest: str

    def __post_init__(self):
        if not self.approver:
            raise ValueError("approver is required")
        if not self.reference:
            raise ValueError("approval reference is required")
        if not self.change_digest:
            raise ValueError("approved change digest is required")

    @classmethod
    def for_preview(
        cls,
        preview: "DryRunExchange",
        *,
        approver: str,
        reference: str,
        body: Any = _UNSET,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> "CommitApproval":
        """Approve exactly the change a successful preview showed.

        ``body`` may name the change to approve; when it differs from the
        previewed body, approval is refused with :class:`PermitMismatch`.
        This keeps a preview success from authorizing a different change.
        """

        if not isinstance(preview, DryRunExchange) or not preview.is_preview:
            raise TypeError("an approval requires a preview exchange")
        if not preview.ok:
            raise PermitMismatch(
                "preview did not succeed",
                check=PermitCheck(
                    False, ("preview status {}".format(preview.status),)))
        check = preview.review(body=body, query_params=query_params)
        if not check.matches:
            raise PermitMismatch(
                "approved change differs from the preview: {}".format(
                    "; ".join(check.reasons)),
                check=check,
            )
        permit = preview.permit
        approved_body = preview.body if body is _UNSET else _serialize(body)
        approved_query = (permit.query if query_params is None
                          else tuple(_query_pairs(query_params)))
        digest = _change_digest(
            resource=permit.resource,
            action=permit.action,
            method=permit.method,
            path=permit.path,
            query=approved_query,
            body_digest=_body_digest(approved_body),
        )
        return cls(
            approver=approver,
            reference=reference,
            change_digest=digest,
        )


@dataclass(frozen=True)
class DryRunPermit:
    """A bound preview or commit approval.

    Create instances with :meth:`preview` or :meth:`commit`.  Both snapshot
    the change immediately, so mutating the caller's object afterwards
    cannot silently change what was approved.
    """

    resource: str
    action: str
    method: str
    path: str
    body: Any
    body_digest: Optional[str]
    query: Tuple[Tuple[str, str], ...]
    dry_run: Optional[str]
    canonical_digest: str
    """Digest including preview/commit mode; useful for audit logging."""

    change_digest: str
    """Digest of the change alone; binds :class:`CommitApproval`."""
    approval: Optional[CommitApproval] = None

    @classmethod
    def preview(
        cls,
        resource: str,
        action: str,
        body: Any = None,
        *,
        method: Optional[str] = None,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> "DryRunPermit":
        """Create a permit for one preview of one exact change.

        The permit adds ``dryRun=All`` to every request it builds.  Callers
        cannot supply ``dryRun`` themselves.
        """

        return cls._create(
            resource=resource,
            action=action,
            body=body,
            method=method,
            query_params=query_params,
            dry_run=DRY_RUN_ALL,
            approval=None,
        )

    @classmethod
    def commit(
        cls,
        resource: str,
        action: str,
        body: Any = None,
        *,
        approval: CommitApproval,
        method: Optional[str] = None,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> "DryRunPermit":
        """Create the independent approval required for the real write.

        ``approval`` is mandatory; a preview exchange or preview permit
        cannot supply it.  The commit permit never carries ``dryRun``.
        """

        if not isinstance(approval, CommitApproval):
            raise TypeError(
                "commit permits require a CommitApproval; a preview result "
                "cannot authorize a write")
        permit = cls._create(
            resource=resource,
            action=action,
            body=body,
            method=method,
            query_params=query_params,
            dry_run=None,
            approval=approval,
        )
        if permit.change_digest != approval.change_digest:
            check = PermitCheck(
                False,
                ("change does not match the approved preview; preview the "
                 "current change and obtain a new approval",),
            )
            raise PermitMismatch(check.describe(), check=check)
        return permit

    @classmethod
    def _create(
        cls,
        *,
        resource: str,
        action: str,
        body: Any,
        method: Optional[str],
        query_params: Optional[Sequence[Tuple[str, str]]],
        dry_run: Optional[str],
        approval: Optional[CommitApproval],
    ) -> "DryRunPermit":
        if not resource:
            raise ValueError("resource is required")
        if not action:
            raise ValueError("action is required")
        if any(key == "dryRun"
               for key, _ in _query_pairs(query_params)):
            raise ValueError(
                "query_params must not set dryRun; the permit owns it")

        resolved_method = _method_for(action, method)
        path = resource if resource.startswith("/") else "/" + resource
        if "{" in path or "}" in path:
            raise ValueError(
                "resource must be a concrete path; resolve path templates "
                "before creating a permit")
        snapshotted = copy.deepcopy(_serialize(body))
        pairs = tuple(_query_pairs(query_params))
        body_digest = _body_digest(snapshotted)
        canonical = _canonical_digest(
            resource=resource,
            action=action,
            method=resolved_method,
            path=path,
            query=pairs,
            body_digest=body_digest,
            dry_run=dry_run,
        )
        change = _change_digest(
            resource=resource,
            action=action,
            method=resolved_method,
            path=path,
            query=pairs,
            body_digest=body_digest,
        )
        return cls(
            resource=resource,
            action=action,
            method=resolved_method,
            path=path,
            body=snapshotted,
            body_digest=body_digest,
            query=pairs,
            dry_run=dry_run,
            canonical_digest=canonical,
            change_digest=change,
            approval=approval,
        )

    @property
    def is_preview(self) -> bool:
        """True when this permit requires ``dryRun=All``."""

        return self.dry_run is not None

    @property
    def is_commit(self) -> bool:
        """True when this permit forbids ``dryRun``."""

        return self.dry_run is None

    def check(
        self,
        *,
        url: str,
        body: Any = _UNSET,
        method: Optional[str] = None,
        action: Optional[str] = None,
    ) -> PermitCheck:
        """Return whether a built request still conforms to this permit.

        ``url`` is the final URL produced by ``ApiClient.param_serialize``.
        When ``body`` is omitted the permit's snapshotted body is compared;
        pass the actual serialized body to compare what would be sent.
        """

        reasons: List[str] = []
        path, pairs = _url_parts(url)
        request_method = (method or self.method).upper()

        if action is not None and action != self.action:
            reasons.append(
                "action {!r} does not match permit action {!r}".format(
                    action, self.action))
        if request_method != self.method:
            reasons.append(
                "method {} does not match permit method {}".format(
                    request_method, self.method))
        if path != self.path:
            reasons.append(
                "path {} does not match permit path {}".format(
                    path, self.path))

        actual_dry_run = _dry_run_values(pairs)
        if self.is_commit:
            if actual_dry_run:
                reasons.append(
                    "commit permit forbids dryRun={}".format(
                        ",".join(actual_dry_run)))
        elif actual_dry_run != [self.dry_run]:
            reasons.append(
                "preview permit requires exactly dryRun={}, found {}".format(
                    self.dry_run, actual_dry_run or "nothing"))

        if _query_digest(pairs) != _query_digest(self.query):
            reasons.append("query parameters changed")

        if body is _UNSET:
            body = self.body
        if _body_digest(body) != self.body_digest:
            reasons.append("body changed")

        return PermitCheck(matches=not reasons, reasons=tuple(reasons))

    def check_request(self, request: "DryRunRequest") -> PermitCheck:
        """Re-check an already built request, including its current body."""

        return self.check(
            url=request.url,
            body=request.body,
            method=request.method,
            action=request.permit.action,
        )

    @property
    def approval_reference(self) -> Optional[str]:
        """The approval reference for a commit permit, if any."""

        if self.approval is None:
            return None
        return self.approval.reference

    def describe(self) -> str:
        return "{} {} {}".format(self.method, self.path, self.action)


@dataclass(frozen=True)
class DryRunRequest:
    """A serialized request that carries a permit."""

    permit: DryRunPermit
    method: str
    url: str
    headers: Mapping[str, str]
    body: Any
    post_params: Tuple[Tuple[str, str], ...]
    query: Tuple[Tuple[str, str], ...]
    check: PermitCheck

    @property
    def query_parameters(self) -> Dict[str, List[str]]:
        """The final query parameters, including any ``dryRun`` values."""

        result: Dict[str, List[str]] = {}
        for key, value in self.query:
            result.setdefault(key, []).append(value)
        return result

    @property
    def dry_run_values(self) -> List[str]:
        return _dry_run_values(self.query)

    def recheck(self) -> PermitCheck:
        """Recompute the check against the request's current body."""

        return self.permit.check_request(self)


@dataclass(frozen=True)
class DryRunRetry:
    """Retry policy for transient responses on permit-scoped writes.

    Every attempt is rebuilt from the permit.  If a rebuilt body, path,
    query, or ``dryRun`` meaning differs, the session raises
    :class:`PermitMismatch` with the reasons instead of sending it.
    """

    max_attempts: int = 1
    delay: float = 0.0
    respect_retry_after: bool = True
    retryable_statuses: frozenset = _DEFAULT_RETRYABLE_STATUSES

    def __post_init__(self):
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.delay < 0:
            raise ValueError("delay must be non-negative")

    def should_retry(self, status: Optional[int]) -> bool:
        return status in self.retryable_statuses

    def wait(self, headers: Mapping[str, str]) -> float:
        wait = self.delay
        if self.respect_retry_after:
            retry_after = _retry_after_seconds(headers)
            if retry_after is not None and retry_after > wait:
                wait = retry_after
        return wait


@dataclass(frozen=True)
class DryRunAttempt:
    """One HTTP attempt in a retry sequence."""

    number: int
    request: DryRunRequest
    sent_body: Any
    status: Optional[int]
    error: Optional[ApiException]
    response_headers: Mapping[str, str]
    response_body: Optional[str]

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status <= 299


@dataclass(frozen=True)
class DryRunExchange:
    """The requests actually sent and the final response received."""

    permit: DryRunPermit
    attempts: Tuple[DryRunAttempt, ...]
    data: Any
    status: Optional[int]
    error: Optional[ApiException]
    response_headers: Mapping[str, str]
    response_body: Optional[str]

    @property
    def request(self) -> DryRunRequest:
        return self.attempts[-1].request

    @property
    def method(self) -> str:
        return self.request.method

    @property
    def executed_method(self) -> str:
        """The HTTP verb actually placed on the wire."""

        return self.request.method

    @property
    def executed_action(self) -> str:
        """The logical action bound by the permit that was executed."""

        return self.permit.action

    @property
    def executed(self) -> Dict[str, Any]:
        """A compact description of what the server actually executed."""

        return {
            "action": self.executed_action,
            "method": self.executed_method,
            "path": _url_parts(self.request.url)[0],
            "status": self.status,
            "dryRun": list(self.dry_run_values),
        }

    @property
    def approval(self) -> Optional[CommitApproval]:
        """The separate approval recorded for this exchange, if any."""

        return self.permit.approval

    @property
    def approval_reference(self) -> Optional[str]:
        """The approval reference for a commit exchange, if any."""

        return self.permit.approval_reference

    @property
    def preview_only(self) -> bool:
        """True when the exchange was sent with preview semantics."""

        return self.is_preview

    @property
    def query(self) -> Tuple[Tuple[str, str], ...]:
        return self.request.query

    @property
    def query_parameters(self) -> Dict[str, List[str]]:
        return self.request.query_parameters

    @property
    def dry_run_values(self) -> List[str]:
        return self.request.dry_run_values

    @property
    def body(self) -> Any:
        """The body snapshot sent on the final attempt.

        This is a copy taken before the request left the process, so later
        caller-side edits cannot change the record.
        """

        return self.attempts[-1].sent_body

    @property
    def body_digest(self) -> Optional[str]:
        """Digest of the body that was actually sent."""

        return _body_digest(self.attempts[-1].sent_body)

    @property
    def body_matches_permit(self) -> bool:
        """Whether every attempt sent the body the permit approved."""

        return all(
            _body_digest(attempt.sent_body) == self.permit.body_digest
            for attempt in self.attempts)

    @property
    def is_preview(self) -> bool:
        return self.permit.is_preview

    @property
    def is_commit(self) -> bool:
        return self.permit.is_commit

    @property
    def ok(self) -> bool:
        return (self.error is None and self.status is not None
                and 200 <= self.status <= 299)

    @property
    def committed(self) -> bool:
        """True only for a successful request sent under a commit permit.

        Every attempt in the exchange must also be free of ``dryRun``, so a
        retried commit cannot sneak preview semantics onto the wire.
        """

        return (self.is_commit and self.ok
                and all(not attempt.request.dry_run_values
                        for attempt in self.attempts))

    @property
    def retried(self) -> bool:
        return len(self.attempts) > 1

    def review(
        self,
        *,
        body: Any = _UNSET,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> PermitCheck:
        """Compare a proposed follow-up change with this preview.

        A successful preview response is evidence only.  This reports
        whether a body or non-``dryRun`` query still matches what was
        previewed; it never creates or authorizes a commit permit.
        """

        if not self.is_preview:
            raise ValueError(
                "only a preview exchange can be used for follow-up review")
        if not self.ok:
            raise ValueError("preview did not succeed")

        reasons: List[str] = []
        proposed_body = (self.body if body is _UNSET
                         else _serialize(body))
        if _body_digest(proposed_body) != self.permit.body_digest:
            reasons.append("body changed")

        proposed_query = self.permit.query
        if query_params is not None:
            proposed_query = tuple(_query_pairs(query_params))
        if _query_digest(proposed_query) != _query_digest(self.permit.query):
            reasons.append("query parameters changed")
        return PermitCheck(matches=not reasons, reasons=tuple(reasons))

    def describe(self) -> str:
        parts = [
            "{} {}".format(self.method, self.request.url),
            "status {}".format(self.status),
            "attempts {}".format(len(self.attempts)),
        ]
        if self.is_preview:
            parts.append("preview only")
        elif self.committed:
            parts.append("committed")
        return ", ".join(parts)


class PermitMismatch(ValueError):
    """Raised before I/O when a request no longer matches its permit."""

    def __init__(self, message: str, *, check: PermitCheck) -> None:
        super().__init__(message)
        self.check = check
        self.reasons = list(check.reasons)


class DryRunSession:
    """Builds and sends writes under a :class:`DryRunPermit`.

    The session holds the real :class:`kubernetes.client.ApiClient` and
    records what its transport actually sent.
    """

    def __init__(self, api_client: ApiClient) -> None:
        if not isinstance(api_client, ApiClient):
            raise TypeError("api_client must be an ApiClient")
        self.api_client = api_client

    def build(
        self,
        permit: DryRunPermit,
        *,
        body: Any = _UNSET,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
        header_params: Optional[Mapping[str, Any]] = None,
        post_params: Optional[Sequence[Tuple[str, str]]] = None,
        auth_settings: Optional[Sequence[str]] = None,
        collection_formats: Optional[Mapping[str, str]] = None,
        _host: Optional[str] = None,
        _request_auth: Optional[Any] = None,
    ) -> DryRunRequest:
        """Serialize the request and verify it against the permit.

        The permit owns the ``dryRun`` query value.  A preview always yields
        ``dryRun=All``; a commit never yields ``dryRun``.  Callers cannot
        override this through ``query_params``.
        """

        if body is _UNSET:
            body = permit.body
        pairs = _query_pairs(permit.query if query_params is None
                             else query_params)
        if any(key == "dryRun" for key, _ in pairs):
            raise ApiValueError(
                "query_params must not set dryRun; the permit owns it")
        if permit.is_preview:
            pairs.append(("dryRun", permit.dry_run))

        method, url, headers, serialized_body, form_params = \
            self.api_client.param_serialize(
                permit.method,
                permit.path,
                path_params={},
                query_params=pairs,
                header_params=dict(header_params or {}),
                body=body,
                post_params=list(post_params or ()),
                files={},
                auth_settings=list(
                    auth_settings
                    if auth_settings is not None else ("BearerToken",)),
                collection_formats=dict(collection_formats or {}),
                _host=_host,
                _request_auth=_request_auth,
            )

        check = permit.check(
            url=url,
            body=serialized_body,
            method=method,
            action=permit.action,
        )
        if not check.matches:
            raise PermitMismatch(check.describe(), check=check)

        _path, parsed_query = _url_parts(url)
        return DryRunRequest(
            permit=permit,
            method=method,
            url=url,
            headers=MappingProxyType(dict(headers)),
            body=copy.deepcopy(serialized_body),
            post_params=tuple(form_params or ()),
            query=tuple(parsed_query),
            check=check,
        )

    def send(
        self,
        permit: DryRunPermit,
        *,
        body: Any = _UNSET,
        query_params: Optional[Sequence[Tuple[str, str]]] = None,
        header_params: Optional[Mapping[str, Any]] = None,
        post_params: Optional[Sequence[Tuple[str, str]]] = None,
        auth_settings: Optional[Sequence[str]] = None,
        collection_formats: Optional[Mapping[str, str]] = None,
        _host: Optional[str] = None,
        _request_auth: Optional[Any] = None,
        retry: Optional[DryRunRetry] = None,
        body_factory: Optional[Callable[[int], Any]] = None,
        request_timeout: Optional[Any] = None,
        response_type: str = "object",
    ) -> DryRunExchange:
        """Send a permit-checked request, optionally retrying transient errors.

        Each attempt rebuilds the request from the permit.  When
        ``body_factory`` is supplied it is called with the zero-based
        attempt number.  A body it returns that no longer matches the
        approved change raises :class:`PermitMismatch` before that attempt
        is sent.  This lets a retry after a transient failure say whether
        its business content still conforms.
        """

        attempts: List[DryRunAttempt] = []
        max_attempts = retry.max_attempts if retry is not None else 1

        for number in range(1, max_attempts + 1):
            attempt_body = (body_factory(number - 1)
                            if body_factory is not None else body)
            request = self.build(
                permit,
                body=attempt_body,
                query_params=query_params,
                header_params=header_params,
                post_params=post_params,
                auth_settings=auth_settings,
                collection_formats=collection_formats,
                _host=_host,
                _request_auth=_request_auth,
            )
            attempt = self._perform(
                request, request_timeout, response_type, number)
            attempts.append(attempt)
            if attempt.ok:
                break
            if (retry is None or number == max_attempts
                    or not retry.should_retry(attempt.status)):
                break
            wait = retry.wait(attempt.response_headers)
            if wait:
                time.sleep(wait)

        final = attempts[-1]
        data = final.error.data if final.error is not None else None
        if final.ok:
            data = self._decode(final.request, final, response_type)

        return DryRunExchange(
            permit=permit,
            attempts=tuple(attempts),
            data=data,
            status=final.status,
            error=final.error,
            response_headers=final.response_headers,
            response_body=final.response_body,
        )

    def send_request(
        self,
        request: DryRunRequest,
        *,
        request_timeout: Optional[Any] = None,
        response_type: str = "object",
    ) -> DryRunExchange:
        """Send an already built request after re-checking it.

        This catches a body or query edited after :meth:`build`; the
        request never leaves the process when the re-check fails.
        """

        check = request.recheck()
        if not check.matches:
            raise PermitMismatch(check.describe(), check=check)
        attempt = self._perform(request, request_timeout, response_type, 1)
        data = attempt.error.data if attempt.error is not None else None
        if attempt.ok:
            data = self._decode(request, attempt, response_type)
        return DryRunExchange(
            permit=request.permit,
            attempts=(attempt,),
            data=data,
            status=attempt.status,
            error=attempt.error,
            response_headers=attempt.response_headers,
            response_body=attempt.response_body,
        )

    def _perform(
        self,
        request: DryRunRequest,
        request_timeout: Optional[Any],
        response_type: str,
        number: int,
    ) -> DryRunAttempt:
        sent_body = copy.deepcopy(request.body)
        status: Optional[int] = None
        error: Optional[ApiException] = None
        headers: Mapping[str, str] = MappingProxyType({})
        body_text: Optional[str] = None
        try:
            response: RESTResponse = self.api_client.call_api(
                request.method,
                request.url,
                header_params=dict(request.headers),
                body=request.body,
                post_params=list(request.post_params),
                _request_timeout=request_timeout,
            )
            raw = response.read()
            headers = MappingProxyType(dict(response.headers or {}))
            body_text = (raw.decode("utf-8")
                         if isinstance(raw, bytes) else raw)
            status = response.status
            if not 200 <= status <= 299:
                error = ApiException(
                    status=status,
                    reason=getattr(response, "reason", None),
                    body=body_text,
                    data=_try_json(body_text),
                )
                error.headers = dict(headers)
        except ApiException as caught:
            status = caught.status
            error = caught
            headers = MappingProxyType(dict(caught.headers or {}))
            body_text = caught.body
            if isinstance(body_text, bytes):
                body_text = body_text.decode("utf-8", errors="replace")
        return DryRunAttempt(
            number=number,
            request=request,
            sent_body=sent_body,
            status=status,
            error=error,
            response_headers=headers,
            response_body=body_text,
        )

    def _decode(
        self,
        request: DryRunRequest,
        attempt: DryRunAttempt,
        response_type: str,
    ) -> Any:
        text = attempt.response_body or ""
        if not text:
            return None
        content_type = None
        for key, value in attempt.response_headers.items():
            if str(key).lower() == "content-type":
                content_type = value
                break
        return self.api_client.deserialize(
            text, response_type, content_type)


def review_preview(
    exchange: DryRunExchange,
    *,
    body: Any = _UNSET,
    query_params: Optional[Sequence[Tuple[str, str]]] = None,
) -> PermitCheck:
    """Compare a proposed change with a successful preview.

    This is the review hook for a release page: it says whether the change
    still matches the preview, and never grants a write.  The return value
    combined with a separate approval should be used to obtain a
    :class:`CommitApproval`.
    """

    return exchange.review(body=body, query_params=query_params)
