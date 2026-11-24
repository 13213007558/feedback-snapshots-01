"""Per-operation egress admission for async endpoint discovery.

The backend is only allowed to open connections to a configured set of
service network addresses.  Endpoint discovery can hand back addresses that
are legal, that still need approval, or that the control plane has withdrawn.

This module puts the policy in one live object (:class:`EgressPolicy`) and
enforces it twice:

* at endpoint selection time in :class:`EgressDiscoveryManager`, where the
  optional/required discovery rules live; and
* at the real connection seam in :class:`EgressTCPConnector`, which is the
  last gate before a socket is established and which writes the actual
  connection records to :class:`ConnectionLedger`.

Policy state is an immutable snapshot swapped atomically, so a control-plane
update (allow/approve/withdraw) is visible to the very next selection and to
request retries -- nothing about an allow decision is cached against the
discovery token or the discovery cache.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

from botocore.discovery import EndpointDiscoveryRefreshFailed

from .discovery import (
    AioEndpointDiscoveryHandler,
    AioEndpointDiscoveryManager,
)
from .httpsession import AIOHTTPSession, _ProxySSLTCPConnector

# Admission reasons.  These are the stable "why" attached to every decision.
REASON_BASELINE = 'baseline_allowed'
REASON_APPROVED = 'explicitly_approved'
REASON_PENDING = 'pending_approval'
REASON_WITHDRAWN = 'withdrawn'
REASON_NOT_LISTED = 'not_allowlisted'
REASON_DEFAULT = 'approved_default'

# Selection roles, propagated to the connection record via context vars.
ROLE_DISCOVERED = 'discovered'
ROLE_FALLBACK = 'default-fallback'
ROLE_DIRECT = 'direct'

# Coarse outcomes used when rendering the ledger.
OUTCOME_CONTINUE = 'CONTINUE'
OUTCOME_FALLBACK = 'FALLBACK'
OUTCOME_STOP = 'STOP'

current_operation: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    'aiobotocore_egress_operation', default=None
)
current_role: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    'aiobotocore_egress_role', default=None
)


@dataclass(frozen=True)
class NetworkAddress:
    """A normalized ``(host, port)`` egress target.

    An entry with ``port is None`` is a host rule that covers every port.
    """

    host: str
    port: int | None = None

    @classmethod
    def parse(cls, value: Any, default_port: int | None = None) -> NetworkAddress:
        if isinstance(value, NetworkAddress):
            return value
        text = str(value).strip()
        if '://' in text:
            parsed = urlparse(text)
            host = (parsed.hostname or '').lower()
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == 'https' else 80
            return cls(host, port)
        if text.startswith('['):  # bracketed IPv6 literal
            host, _, remainder = text[1:].partition(']')
            remainder = remainder.lstrip(':')
            port = int(remainder) if remainder else default_port
            return cls(host.lower(), port)
        if text.count(':') == 1:
            host, port_text = text.rsplit(':', 1)
            try:
                return cls(host.lower(), int(port_text))
            except ValueError:
                # Probably an unbracketed IPv6 value; keep the whole string.
                return cls(text.lower(), default_port)
        return cls(text.lower(), default_port)

    def covers(self, other: NetworkAddress) -> bool:
        if self.host != other.host:
            return False
        if self.port is None:
            return True
        return self.port == other.port

    def origin(self, scheme: str = 'http') -> str:
        if self.port is None:
            return f'{scheme}://{self.host}'
        return f'{scheme}://{self.host}:{self.port}'

    def __str__(self) -> str:
        return f'{self.host}:{self.port}' if self.port is not None else self.host


def _contains(rules: Iterable[NetworkAddress], address: NetworkAddress) -> bool:
    return any(rule.covers(address) for rule in rules)


def _blocker_for(reason: str) -> str:
    return {
        REASON_WITHDRAWN: 'control-plane:withdrawn-address',
        REASON_PENDING: 'approval-workflow:pending-approval',
        REASON_NOT_LISTED: 'egress-policy:address-not-allowed',
    }.get(reason, 'egress-policy')


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    address: NetworkAddress
    reason: str
    policy_version: int
    blocker: str | None = None
    operation: str | None = None
    required: bool | None = None
    detail: str = ''

    def describe(self) -> str:
        base = f'{self.address} -> {self.reason}@v{self.policy_version}'
        return f'{base} [{self.blocker}]' if self.blocker else base


@dataclass(frozen=True)
class _Snapshot:
    version: int
    allowed: frozenset[NetworkAddress]
    approved: frozenset[NetworkAddress]
    defaults: frozenset[NetworkAddress]
    pending: frozenset[NetworkAddress]
    withdrawn: frozenset[NetworkAddress]


class EgressPolicy:
    """Live admission policy backed by an atomically swapped snapshot."""

    def __init__(
        self,
        allowed: Iterable[Any] = (),
        approved: Iterable[Any] = (),
        default_endpoints: Iterable[Any] = (),
    ) -> None:
        self._lock = threading.RLock()
        self._snapshot = _Snapshot(
            version=1,
            allowed=frozenset(NetworkAddress.parse(a) for a in allowed),
            approved=frozenset(NetworkAddress.parse(a) for a in approved),
            defaults=frozenset(
                NetworkAddress.parse(a) for a in default_endpoints
            ),
            pending=frozenset(),
            withdrawn=frozenset(),
        )

    @property
    def version(self) -> int:
        return self._snapshot.version

    @property
    def snapshot(self) -> _Snapshot:
        return self._snapshot

    def _replace(self, **changes: Any) -> _Snapshot:
        with self._lock:
            current = self._snapshot
            snapshot = _Snapshot(
                version=current.version + 1,
                allowed=changes.get('allowed', current.allowed),
                approved=changes.get('approved', current.approved),
                defaults=changes.get('defaults', current.defaults),
                pending=changes.get('pending', current.pending),
                withdrawn=changes.get('withdrawn', current.withdrawn),
            )
            self._snapshot = snapshot
            return snapshot

    def allow(self, *addresses: Any) -> int:
        with self._lock:
            current = self._snapshot
            extra = {NetworkAddress.parse(a) for a in addresses}
            self._replace(allowed=current.allowed | frozenset(extra))
            return self.version

    def approve(self, address: Any, *, ticket: str | None = None) -> int:
        address = NetworkAddress.parse(address)
        with self._lock:
            current = self._snapshot
            # Explicit approval clears a pending marker and even a prior
            # withdrawal: a later control-plane decision re-admits the target.
            pending = frozenset(a for a in current.pending if not a.covers(address))
            withdrawn = frozenset(
                a for a in current.withdrawn if not a.covers(address)
            )
            approved = current.approved | {address}
            self._replace(
                approved=approved, pending=pending, withdrawn=withdrawn
            )
            return self.version

    def withdraw(self, address: Any, *, reason: str | None = None) -> int:
        address = NetworkAddress.parse(address)
        with self._lock:
            current = self._snapshot
            withdrawn = current.withdrawn | {address}
            approved = frozenset(
                a for a in current.approved if not a.covers(address)
            )
            pending = frozenset(
                a for a in current.pending if not a.covers(address)
            )
            self._replace(
                withdrawn=withdrawn, approved=approved, pending=pending
            )
            return self.version

    def apply_update(
        self,
        *,
        allow: Iterable[Any] | None = None,
        approve: Iterable[Any] | None = None,
        withdraw: Iterable[Any] | None = None,
    ) -> int:
        """Apply one atomic control-plane push and bump the version once."""
        with self._lock:
            if allow:
                current = self._snapshot
                extra = {NetworkAddress.parse(a) for a in allow}
                self._replace(allowed=current.allowed | frozenset(extra))
            for address in approve or ():
                self.approve(address)
            for address in withdraw or ():
                self.withdraw(address)
            return self.version

    def observe(self, address: Any) -> AdmissionDecision:
        """Register a freshly discovered address in the approval queue.

        Unknown, non-withdrawn addresses become ``pending``.  Returns the
        resulting admission decision.
        """
        address = NetworkAddress.parse(address)
        snapshot = self._snapshot
        known = (
            _contains(snapshot.allowed, address)
            or _contains(snapshot.approved, address)
            or _contains(snapshot.withdrawn, address)
        )
        if not known and not _contains(snapshot.pending, address):
            with self._lock:
                current = self._snapshot
                self._replace(pending=current.pending | {address})
        return self.admit(address)

    def admit(
        self,
        address: Any,
        *,
        operation: str | None = None,
        required: bool | None = None,
    ) -> AdmissionDecision:
        address = NetworkAddress.parse(address)
        snapshot = self._snapshot
        version = snapshot.version

        def decision(allowed: bool, reason: str, detail: str = '') -> AdmissionDecision:
            return AdmissionDecision(
                allowed=allowed,
                address=address,
                reason=reason,
                policy_version=version,
                blocker=None if allowed else _blocker_for(reason),
                operation=operation,
                required=required,
                detail=detail,
            )

        # Withdrawal wins over stale cache entries and prior allow rules.
        if _contains(snapshot.withdrawn, address):
            return decision(False, REASON_WITHDRAWN, 'address withdrawn')
        if _contains(snapshot.allowed, address):
            reason = (
                REASON_DEFAULT
                if _contains(snapshot.defaults, address)
                else REASON_BASELINE
            )
            return decision(True, reason)
        if _contains(snapshot.approved, address):
            return decision(True, REASON_APPROVED)
        if _contains(snapshot.pending, address):
            return decision(False, REASON_PENDING, 'explicit approval required')
        return decision(False, REASON_NOT_LISTED, 'outside configured egress set')


@dataclass
class LedgerRecord:
    seq: int
    kind: str
    at: float
    monotonic: float
    address: str | None = None
    host: str | None = None
    port: int | None = None
    operation: str | None = None
    role: str | None = None
    outcome: str | None = None
    reason: str | None = None
    blocker: str | None = None
    policy_version: int | None = None
    transport: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def compact(self) -> str:
        target = self.address or '-'
        parts = [
            f'#{self.seq:<2}',
            f'{self.kind:<19}',
            f'{self.outcome or "-":<8}',
            f'{self.operation or "-":<10}',
            f'{self.role or "-":<16}',
            f'{target:<22}',
            self.blocker or self.reason or '',
        ]
        return ' '.join(part for part in parts if part)


class ConnectionLedger:
    """Ordered, thread-safe record of actual connection decisions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[LedgerRecord] = []
        self._seq = 0

    def _add(self, kind: str, **kwargs: Any) -> LedgerRecord:
        with self._lock:
            self._seq += 1
            record = LedgerRecord(
                seq=self._seq,
                kind=kind,
                at=time.time(),
                monotonic=time.monotonic(),
                **kwargs,
            )
            self._records.append(record)
            return record

    def connected(self, decision: AdmissionDecision, **kwargs: Any) -> LedgerRecord:
        address = decision.address
        return self._add(
            'connected',
            address=str(address),
            host=address.host,
            port=address.port,
            reason=decision.reason,
            policy_version=decision.policy_version,
            outcome=OUTCOME_CONTINUE
            if kwargs.get('role') == ROLE_DISCOVERED
            else OUTCOME_FALLBACK
            if kwargs.get('role') == ROLE_FALLBACK
            else None,
            **kwargs,
        )

    def connect_blocked(
        self, decision: AdmissionDecision, **kwargs: Any
    ) -> LedgerRecord:
        address = decision.address
        return self._add(
            'connect_blocked',
            address=str(address),
            host=address.host,
            port=address.port,
            reason=decision.reason,
            blocker=decision.blocker,
            policy_version=decision.policy_version,
            outcome=OUTCOME_STOP,
            **kwargs,
        )

    def stopped(self, **kwargs: Any) -> LedgerRecord:
        return self._add('stop', outcome=OUTCOME_STOP, **kwargs)

    def fallback(self, decision: AdmissionDecision, **kwargs: Any) -> LedgerRecord:
        address = decision.address
        return self._add(
            'fallback-selected',
            address=str(address),
            host=address.host,
            port=address.port,
            reason=decision.reason,
            policy_version=decision.policy_version,
            outcome=OUTCOME_FALLBACK,
            **kwargs,
        )

    def selection(self, **kwargs: Any) -> LedgerRecord:
        decisions = kwargs.pop('decisions', [])
        chosen = kwargs.pop('chosen', None)
        required = kwargs.pop('required', None)
        note = kwargs.pop('note', None)
        extra = kwargs.pop('extra', {})
        return self._add(
            'discovery-selection',
            address=str(chosen) if chosen else None,
            detail={
                'required': required,
                'note': note,
                'candidates': [d.describe() for d in decisions],
                **extra,
            },
            **kwargs,
        )

    def connect_failed(self, decision: AdmissionDecision, **kwargs: Any) -> LedgerRecord:
        address = decision.address
        return self._add(
            'connect_failed',
            address=str(address),
            host=address.host,
            port=address.port,
            reason=decision.reason,
            policy_version=decision.policy_version,
            **kwargs,
        )

    @property
    def records(self) -> list[LedgerRecord]:
        with self._lock:
            return list(self._records)

    def of_kind(self, *kinds: str) -> list[LedgerRecord]:
        return [r for r in self.records if r.kind in kinds]

    @property
    def connections(self) -> list[LedgerRecord]:
        return self.of_kind('connected')

    @property
    def blocks(self) -> list[LedgerRecord]:
        return self.of_kind('connect_blocked', 'stop')

    def targets(self) -> list[str]:
        return [r.address for r in self.connections if r.address]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._seq = 0

    def render(self, *, include_selection: bool = True) -> str:
        rows = []
        for record in self.records:
            if record.kind == 'discovery-selection' and not include_selection:
                continue
            rows.append(record.compact())
        header = (
            '#   KIND                OUTCOME  OP         ROLE             '
            'TARGET                 REASON/BLOCKER'
        )
        return '\n'.join([header, *rows])


class EgressDeniedError(Exception):
    """Base class for every egress block; marked so retries stop at once."""

    egress_block = True

    def __init__(
        self,
        message: str,
        *,
        decision: AdmissionDecision | None = None,
        decisions: list[AdmissionDecision] | None = None,
        operation: str | None = None,
        blocker: str | None = None,
        policy_version: int | None = None,
    ) -> None:
        super().__init__(message)
        self.decision = decision
        self.decisions = list(decisions or ([decision] if decision else []))
        self.operation = operation
        self.blocker = blocker or (decision.blocker if decision else None)
        self.policy_version = policy_version or (
            decision.policy_version if decision else None
        )


class EgressConnectionBlocked(EgressDeniedError):
    """The transport gate refused to establish a physical connection."""


class UnapprovedDefaultEndpoint(EgressDeniedError):
    """An optional operation's default endpoint is itself not approved."""


class RequiredDiscoveryBlocked(EndpointDiscoveryRefreshFailed):
    """A required-discovery operation has no admissible discovery address."""

    egress_block = True
    fmt = 'Endpoint discovery admission blocked for {operation}: {reasons}'

    def __init__(
        self,
        *,
        operation: str,
        decisions: list[AdmissionDecision] | None = None,
        blocker: str | None = None,
        reasons: str | None = None,
        discovery_note: str | None = None,
        policy_version: int | None = None,
    ) -> None:
        self.operation = operation
        self.decisions = list(decisions or [])
        self.blocker = blocker or _dominant_blocker(self.decisions)
        if self.blocker is None and not self.decisions:
            self.blocker = 'discovery:refresh-failed'
        self.policy_version = policy_version or (
            self.decisions[0].policy_version if self.decisions else None
        )
        self.discovery_note = discovery_note
        rendered = reasons or '; '.join(
            d.describe() for d in self.decisions
        )
        if not rendered:
            rendered = 'discovery returned no usable endpoint'
        self.reasons = rendered
        super().__init__(operation=operation, reasons=rendered)


def _dominant_blocker(
    decisions: list[AdmissionDecision],
) -> str | None:
    decision = _dominant_decision(decisions)
    return decision.blocker if decision else None


def _dominant_decision(
    decisions: list[AdmissionDecision],
) -> AdmissionDecision | None:
    # Withdrawal is the most important source to surface, then pending, then
    # the generic allowlist.
    for reason in (
        REASON_WITHDRAWN,
        REASON_PENDING,
        REASON_NOT_LISTED,
    ):
        for decision in decisions:
            if not decision.allowed and decision.reason == reason:
                return decision
    for decision in decisions:
        if not decision.allowed:
            return decision
    return None


class EgressGate:
    """Combines policy + ledger and is shared by selection and transport."""

    def __init__(
        self,
        policy: EgressPolicy | None = None,
        ledger: ConnectionLedger | None = None,
        *,
        transport: str = 'aiohttp-connector',
    ) -> None:
        self.policy = policy or EgressPolicy()
        self.ledger = ledger or ConnectionLedger()
        self.transport = transport

    def check(
        self,
        address: Any,
        *,
        operation: str | None = None,
        role: str | None = None,
        transport: str | None = None,
    ) -> AdmissionDecision:
        decision = self.policy.admit(address, operation=operation)
        if not decision.allowed:
            self.ledger.connect_blocked(
                decision,
                operation=operation,
                role=role,
                transport=transport or self.transport,
            )
            raise EgressConnectionBlocked(
                f'Refusing to connect to {decision.address}: '
                f'{decision.reason} ({decision.blocker})',
                decision=decision,
                operation=operation,
                blocker=decision.blocker,
                policy_version=decision.policy_version,
            )
        return decision

    def confirm(
        self,
        decision: AdmissionDecision,
        *,
        operation: str | None = None,
        role: str | None = None,
        transport: str | None = None,
    ) -> LedgerRecord:
        return self.ledger.connected(
            decision,
            operation=operation,
            role=role,
            transport=transport or self.transport,
        )

    def required_stop(
        self,
        *,
        operation: str,
        decisions: list[AdmissionDecision],
        discovery_note: str | None = None,
    ) -> RequiredDiscoveryBlocked:
        blocker = _dominant_blocker(decisions) or (
            'discovery:refresh-failed'
        )
        target = _dominant_decision(decisions)
        error = RequiredDiscoveryBlocked(
            operation=operation,
            decisions=decisions,
            blocker=blocker,
            discovery_note=discovery_note,
        )
        self.ledger.stopped(
            operation=operation,
            blocker=blocker,
            reason=discovery_note or 'no-admissible-discovery-endpoint',
            policy_version=error.policy_version,
            address=str(target.address) if target else None,
            host=target.address.host if target else None,
            port=target.address.port if target else None,
            detail={'candidates': [d.describe() for d in decisions]},
        )
        return error

    def default_denied(
        self,
        *,
        operation: str,
        decision: AdmissionDecision,
        discovery_decisions: list[AdmissionDecision],
    ) -> UnapprovedDefaultEndpoint:
        default_blocker = 'egress-policy:default-endpoint-not-approved'
        error = UnapprovedDefaultEndpoint(
            f'Optional operation {operation} cannot fall back to default '
            f'endpoint: {decision.describe()}',
            decision=decision,
            decisions=[*discovery_decisions, decision],
            operation=operation,
            blocker=default_blocker,
            policy_version=decision.policy_version,
        )
        self.ledger.stopped(
            operation=operation,
            blocker=default_blocker,
            reason='default-endpoint-not-approved',
            policy_version=decision.policy_version,
            address=str(decision.address),
            host=decision.address.host,
            port=decision.address.port,
            detail={
                'candidates': [
                    d.describe() for d in [*discovery_decisions, decision]
                ]
            },
        )
        return error


class EgressDiscoveryManager(AioEndpointDiscoveryManager):
    """Discovery manager that re-admits every endpoint against live policy."""

    def __init__(
        self,
        client: Any,
        *,
        gate: EgressGate,
        discovery_source: Any | None = None,
        default_endpoint: Any | None = None,
        always_discover: bool = True,
    ) -> None:
        super().__init__(client, always_discover=always_discover)
        self._egress_gate = gate
        self._discovery_source = discovery_source
        if default_endpoint is None:
            default_endpoint = getattr(
                getattr(client, 'meta', None), 'endpoint_url', None
            )
        self._default_address = (
            NetworkAddress.parse(default_endpoint)
            if default_endpoint
            else None
        )

    def _describe_endpoints(self, **kwargs: Any) -> Any:
        if self._discovery_source is not None:
            return self._discovery_source.describe_endpoints(**kwargs)
        return super()._describe_endpoints(**kwargs)

    async def describe_endpoint(self, **kwargs: Any) -> str | None:
        operation = kwargs['Operation']
        required = self._model.discovery_required_for(operation)

        if not self._always_discover and not required:
            current_role.set(ROLE_DIRECT)
            return None

        cache_key = self._create_cache_key(**kwargs)
        endpoints, note = await self._candidate_endpoints(
            cache_key, kwargs, required
        )

        decisions: list[AdmissionDecision] = []
        chosen_raw: str | None = None
        chosen_address: NetworkAddress | None = None
        if endpoints:
            for endpoint in endpoints:
                address = NetworkAddress.parse(endpoint['Address'])
                self._egress_gate.policy.observe(address)
                decision = self._egress_gate.policy.admit(
                    address, operation=operation, required=required
                )
                decisions.append(decision)
                if decision.allowed and chosen_raw is None:
                    chosen_raw = endpoint['Address']
                    chosen_address = address

        self._egress_gate.ledger.selection(
            operation=operation,
            required=required,
            note=note,
            decisions=decisions,
            chosen=chosen_address,
        )

        if chosen_raw is not None:
            current_role.set(ROLE_DISCOVERED)
            return chosen_raw

        # No *qualified* discovery address.  Required operations stop; optional
        # operations may fall back, but only to an approved default endpoint.
        if required:
            raise self._egress_gate.required_stop(
                operation=operation,
                decisions=decisions,
                discovery_note=note,
            )

        if self._default_address is None:
            raise self._egress_gate.required_stop(
                operation=operation,
                decisions=decisions,
                discovery_note='no-default-endpoint-configured',
            )

        default_decision = self._egress_gate.policy.admit(
            self._default_address, operation=operation, required=False
        )
        if default_decision.allowed:
            current_role.set(ROLE_FALLBACK)
            self._egress_gate.ledger.fallback(
                default_decision, operation=operation
            )
            return None

        raise self._egress_gate.default_denied(
            operation=operation,
            decision=default_decision,
            discovery_decisions=decisions,
        )

    async def _candidate_endpoints(
        self, cache_key: tuple, kwargs: dict, required: bool
    ) -> tuple[list[dict] | None, str]:
        endpoints = self._get_current_endpoints(cache_key)
        if endpoints:
            return endpoints, 'warm-cache'

        recently_failed = self._recently_failed(cache_key)
        if not recently_failed:
            endpoints = await self._refresh_current_endpoints(**kwargs)
            if endpoints:
                return endpoints, 'fresh-discovery'

        stale = self._cache.get(cache_key)
        if stale:
            return stale, 'stale-cache'

        if required and recently_failed:
            endpoints = await self._refresh_current_endpoints(**kwargs)
            if endpoints:
                return endpoints, 'fresh-retry-discovery'

        return None, 'discovery-unavailable'


class EgressDiscoveryHandler(AioEndpointDiscoveryHandler):
    """Tags the task with the operation so connect records can attribute it."""

    async def discover_endpoint(
        self, request: Any, operation_name: str | None = None, **kwargs: Any
    ) -> None:
        if operation_name is not None:
            current_operation.set(operation_name)
        await super().discover_endpoint(request, operation_name, **kwargs)


def _exception_is_egress_block(exc: BaseException | None) -> bool:
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if getattr(current, 'egress_block', False):
            return True
        kwargs = getattr(current, 'kwargs', None)
        inner = kwargs.get('error') if isinstance(kwargs, dict) else None
        if isinstance(inner, BaseException):
            current = inner
            continue
        current = current.__cause__ or current.__context__
    return False


def deny_egress_retry(**kwargs: Any) -> bool | None:
    """``needs-retry`` handler: security blocks must never be retried."""
    if _exception_is_egress_block(kwargs.get('caught_exception')):
        return False
    return None


class EgressTCPConnector(_ProxySSLTCPConnector):
    """aiohttp connector that enforces egress at the real connect seam."""

    def __init__(self, *args: Any, egress_gate: EgressGate, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._egress_gate = egress_gate

    async def _wrap_create_connection(
        self,
        *args: Any,
        addr_infos: list,
        req: Any,
        timeout: Any,
        client_error: type[Exception] | None = None,
        **kwargs: Any,
    ) -> tuple[Any, Any]:
        address = NetworkAddress(
            host=(req.url.raw_host or '').lower(), port=req.port
        )
        operation = current_operation.get()
        role = current_role.get()
        decision = self._egress_gate.check(
            address, operation=operation, role=role
        )
        try:
            result = await self._egress_dial(
                args, addr_infos, req, timeout, client_error, kwargs
            )
        except BaseException:
            self._egress_gate.ledger.connect_failed(
                decision, operation=operation, role=role
            )
            raise
        self._egress_gate.confirm(
            decision, operation=operation, role=role
        )
        return result

    async def _egress_dial(
        self,
        args: tuple,
        addr_infos: list,
        req: Any,
        timeout: Any,
        client_error: type[Exception] | None,
        kwargs: dict,
    ) -> tuple[Any, Any]:
        return await super()._wrap_create_connection(
            *args,
            addr_infos=addr_infos,
            req=req,
            timeout=timeout,
            client_error=client_error,
            **kwargs,
        )


class GuardedAIOHTTPSession(AIOHTTPSession):
    """Session that builds :class:`EgressTCPConnector` with a gate."""

    egress_gate: EgressGate | None = None
    egress_connector_cls: type[EgressTCPConnector] = EgressTCPConnector

    async def _create_connector(self, proxy_url: str | None):
        if self._verify or self._cert_file or proxy_url:
            ssl_context, proxy_ssl_context = await asyncio.to_thread(
                self._build_ssl_contexts, proxy_url
            )
        else:
            ssl_context, proxy_ssl_context = self._build_ssl_contexts(
                proxy_url
            )
        return self.egress_connector_cls(
            egress_gate=self.egress_gate,
            limit=self._max_pool_connections,
            ssl=ssl_context,
            proxy_ssl_context=proxy_ssl_context,
            **self._connector_args,
        )


def guarded_aiohttp_session_class(gate: EgressGate) -> type[AIOHTTPSession]:
    class _BoundGuardedSession(GuardedAIOHTTPSession):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.egress_gate = gate

    return _BoundGuardedSession


@dataclass
class EgressHandle:
    client: Any
    gate: EgressGate
    manager: EgressDiscoveryManager
    handler: EgressDiscoveryHandler

    @property
    def policy(self) -> EgressPolicy:
        return self.gate.policy

    @property
    def ledger(self) -> ConnectionLedger:
        return self.gate.ledger


def install_endpoint_egress(
    client: Any,
    policy: EgressPolicy | None = None,
    *,
    gate: EgressGate | None = None,
    ledger: ConnectionLedger | None = None,
    discovery_source: Any | None = None,
    default_endpoint: str | None = None,
    always_discover: bool = True,
) -> EgressHandle:
    """Attach per-operation discovery admission + a no-retry guard to a client.

    Pair the returned gate with :func:`guarded_aiohttp_session_class` (or the
    test transport double) so the same policy backs the actual connection
    seam.  Clients created with an explicit ``endpoint_url`` do not get the
    stock discovery handler, so installing here gives a single handler.
    """
    if gate is None:
        gate = EgressGate(policy or EgressPolicy(), ledger=ledger)
    manager = EgressDiscoveryManager(
        client,
        gate=gate,
        discovery_source=discovery_source,
        default_endpoint=default_endpoint
        or getattr(getattr(client, 'meta', None), 'endpoint_url', None),
        always_discover=always_discover,
    )
    handler = EgressDiscoveryHandler(manager)
    service_id = client.meta.service_model.service_id.hyphenize()
    handler.register(client.meta.events, service_id)
    client.meta.events.register_first(
        f'needs-retry.{service_id}', deny_egress_retry
    )
    return EgressHandle(
        client=client, gate=gate, manager=manager, handler=handler
    )
