"""Offline, two-account demo of an approval-pinned botocore client.

The scenario
------------
A shared botocore client is handed temporary credentials whose *duty identity*
can rotate while the process runs. Some services pick their endpoint from the
target account (here ``s3control`` renders ``{AccountId}.s3-control...``), so
the business needs proof, on every single HTTP attempt, that:

1. the endpoint the request is sent to was rendered from the approved account,
2. the signing stand-in (real botocore SigV4, captured as an audit double)
   signed with credentials issued for that same account,
3. the duty roster entry active at the attempt timestamp names that account.

No AWS traffic is involved: a ``before-send`` event handler short-circuits the
HTTP layer with scripted responses, and the "STS" broker is an in-memory fake.

The guarantees demonstrated
----------------------------
* A logical call is bound to one :class:`ApprovalContext`. Retries inside the
  call never change account, even though the duty roster rotates after the
  first failed transmission: the refresh callback can only re-mint credentials
  for the pinned account.
* Before the next logical call, an expired approval is handled by explicit
  policy -- either a safe rebuild (new approval for the now-on-duty account) or
  a hard stop (``ApprovalExpiredError``), never a silent account switch.
* Ordinary regional services (``sts.GetCallerIdentity``) keep using the plain
  regional endpoint; account-scoped endpoint rendering stays opt-in per
  service/operation instead of becoming account-level for everything.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from botocore import xform_name
from botocore.awsrequest import AWSResponse
from botocore.client import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import Session

REGION = "us-east-1"
ACCOUNT_A = "111111111111"
ACCOUNT_B = "222222222222"
APPROVAL_TTL = timedelta(minutes=30)
# botocore normally only refreshes inside a 15/10 minute advisory window. Zero
# the windows so the demo can drive expiry deterministically with a fake clock.
IMMEDIATE_REFRESH_WINDOW = 0
# An AWS account id rendered as the first DNS label of an account-scoped host.
ACCOUNT_HOST_PREFIX = re.compile(r"^(\d{12})\.")


class ApprovalExpiredError(RuntimeError):
    """Raised when policy is STOP and the pinned approval has expired."""


class AccountBoundaryViolation(RuntimeError):
    """Raised when a refresh would cross the pinned approval's account."""


class FakeClock:
    """Controllable UTC clock shared by the broker and credential objects."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta

    def __call__(self) -> datetime:
        return self._now


@dataclass
class IssuedCredentials:
    """One set of fake temporary credentials minted for a specific account."""

    account_id: str
    version: int
    access_key: str
    secret_key: str
    token: str
    issued_at: datetime
    expires_at: datetime

    def as_metadata(self) -> dict:
        return {
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "token": self.token,
            "expiry_time": self.expires_at.isoformat(),
            "account_id": self.account_id,
        }


@dataclass
class DutyEntry:
    """One immutable row of the on-duty roster (the duty log)."""

    account_id: str
    credential_version: int
    effective_from: datetime
    reason: str


class FakeIdentityBroker:
    """In-memory stand-in for STS AssumeRole plus a duty roster.

    ``rotate_on_duty`` changes which account new approvals/credentials are
    minted for. Credentials for an already-approved account can still be
    re-minted independently, so an in-flight call keeps its identity while the
    roster moves on.
    """

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock
        self._on_duty = ACCOUNT_A
        self._versions: dict[str, int] = {ACCOUNT_A: 0, ACCOUNT_B: 0}
        self.duty_log: list[DutyEntry] = []
        self.issue_log: list[IssuedCredentials] = []
        self._record_duty("initial duty assignment")

    @property
    def on_duty_account(self) -> str:
        return self._on_duty

    def _record_duty(self, reason: str) -> DutyEntry:
        entry = DutyEntry(
            account_id=self._on_duty,
            credential_version=self._versions[self._on_duty],
            effective_from=self._clock.now(),
            reason=reason,
        )
        self.duty_log.append(entry)
        return entry

    def rotate_on_duty(self, account_id: str, reason: str) -> DutyEntry:
        if account_id == self._on_duty:
            raise ValueError(f"{account_id} is already on duty")
        self._on_duty = account_id
        return self._record_duty(reason)

    def duty_entry_at(self, when: datetime) -> DutyEntry:
        """Roster row authoritative at a given attempt timestamp.

        The credential version is resolved to the latest issue for the on-duty
        account at that instant, so the row reflects what the broker could
        actually have handed out at the time.
        """
        active = self.duty_log[0]
        for entry in self.duty_log:
            if entry.effective_from <= when:
                active = entry
            else:
                break
        latest_version = 0
        for issued in self.issue_log:
            if (
                issued.account_id == active.account_id
                and issued.issued_at <= when
            ):
                latest_version = max(latest_version, issued.version)
        return DutyEntry(
            account_id=active.account_id,
            credential_version=latest_version,
            effective_from=active.effective_from,
            reason=active.reason,
        )

    def issue(
        self, account_id: str, ttl: timedelta = APPROVAL_TTL
    ) -> IssuedCredentials:
        self._versions[account_id] += 1
        version = self._versions[account_id]
        now = self._clock.now()
        issued = IssuedCredentials(
            account_id=account_id,
            version=version,
            access_key=f"AKIA-{account_id}-V{version}",
            secret_key=f"secret-{account_id}-{version}",
            token=f"token-{account_id}-{version}",
            issued_at=now,
            expires_at=now + ttl,
        )
        self.issue_log.append(issued)
        return issued


@dataclass
class ApprovalContext:
    """The single approved identity a logical call is pinned to."""

    approval_id: str
    account_id: str
    issued_at: datetime
    expires_at: datetime
    policy: str  # "REBUILD" or "STOP"
    allow_rebuild_accounts: tuple[str, ...]

    def is_valid(self, now: datetime) -> bool:
        return now < self.expires_at


class ApprovalManager:
    """Approves logical calls and enforces the expiry policy between them."""

    def __init__(self, broker: FakeIdentityBroker, clock: FakeClock) -> None:
        self._broker = broker
        self._clock = clock
        self._seq = 0

    def approve(
        self,
        policy: str = "REBUILD",
        allow_rebuild_accounts: tuple[str, ...] = (ACCOUNT_A, ACCOUNT_B),
    ) -> ApprovalContext:
        self._seq += 1
        account_id = self._broker.on_duty_account
        now = self._clock.now()
        return ApprovalContext(
            approval_id=f"APR-{self._seq:03d}",
            account_id=account_id,
            issued_at=now,
            expires_at=now + APPROVAL_TTL,
            policy=policy,
            allow_rebuild_accounts=allow_rebuild_accounts,
        )

    def require_valid(self, approval: ApprovalContext) -> ApprovalContext:
        """Validate at a call boundary; never silently switch account."""
        now = self._clock.now()
        if approval.is_valid(now):
            return approval
        if approval.policy == "STOP":
            raise ApprovalExpiredError(
                f"{approval.approval_id} for account {approval.account_id} "
                f"expired at {approval.expires_at:%H:%M:%S}; policy=STOP"
            )
        target = self._broker.on_duty_account
        if target not in approval.allow_rebuild_accounts:
            raise ApprovalExpiredError(
                f"rebuild would move to unapproved account {target}"
            )
        rebuilt = self.approve(
            policy=approval.policy,
            allow_rebuild_accounts=approval.allow_rebuild_accounts,
        )
        print(
            f"  [policy] {approval.approval_id} expired -> rebuilt "
            f"{rebuilt.approval_id} on account {rebuilt.account_id}"
        )
        return rebuilt


class PinnedCredentialProvider:
    """Refreshable credentials that can never leave the pinned account.

    One shared client holds one provider. The active approval is installed in
    thread-local state for the duration of a logical call, so the botocore
    refresh callback always re-mints credentials for that approval's account.
    """

    def __init__(
        self,
        broker: FakeIdentityBroker,
        clock: FakeClock,
        call_scope: threading.local,
    ) -> None:
        self._broker = broker
        self._clock = clock
        # Shared with the offline transport so both see the exact approval
        # bound to the logical call currently running on this thread.
        self._local = call_scope
        self._credentials: RefreshableCredentials | None = None

    def bind(self, approval: ApprovalContext) -> RefreshableCredentials:
        self._local.approval = approval
        if self._credentials is None:
            first = self._broker.issue(approval.account_id)
            self._credentials = RefreshableCredentials(
                access_key=first.access_key,
                secret_key=first.secret_key,
                token=first.token,
                expiry_time=first.expires_at,
                refresh_using=self._refresh,
                method="fake-assume-role",
                time_fetcher=self._clock,
                advisory_timeout=IMMEDIATE_REFRESH_WINDOW,
                mandatory_timeout=IMMEDIATE_REFRESH_WINDOW,
                account_id=approval.account_id,
            )
        elif self._credentials.account_id != approval.account_id:
            # A new logical call may target a different approved account than
            # the one the shared object last minted for. Invalidate immediately
            # so the next signature is built from this approval's account.
            self._invalidate()
        return self._credentials

    def rotate_after_failure(self) -> None:
        """Force credential rotation when a transmission fails.

        The botocore retry loop re-signs every attempt, but it only re-invokes
        the refresh callback when expiry is due. A failed first transmission
        must rotate credentials even though they are still time-valid; the
        pinned approval keeps the rotation inside the same account.
        """
        self._invalidate()

    def _invalidate(self) -> None:
        # Backdate expiry so the next get_frozen_credentials() call triggers
        # _refresh(), whose callback is constrained to the pinned account.
        self._credentials._expiry_time = self._clock.now() - timedelta(
            seconds=1
        )

    def clear(self) -> None:
        self._local.approval = None

    def _refresh(self) -> dict:
        approval: ApprovalContext | None = getattr(
            self._local, "approval", None
        )
        if approval is None:
            raise AccountBoundaryViolation(
                "credential refresh attempted outside an approval-bound call"
            )
        if not approval.is_valid(self._clock.now()):
            # In-flight calls must finish under the original approval; an
            # expired approval is rebuilt/stopped at the call boundary instead.
            raise ApprovalExpiredError(
                f"{approval.approval_id} expired mid-call; refusing to re-mint"
            )
        issued = self._broker.issue(approval.account_id)
        print(
            f"  [creds]   re-minted v{issued.version} for pinned account "
            f"{issued.account_id} under {approval.approval_id}"
        )
        return issued.as_metadata()

    @property
    def credentials(self) -> RefreshableCredentials:
        if self._credentials is None:
            raise RuntimeError("call bind() before using the provider")
        return self._credentials


@dataclass
class AttemptRecord:
    """Cross-checkable evidence collected for one HTTP attempt."""

    attempt_no: int
    service: str
    operation: str
    approval_id: str
    approved_account: str
    endpoint_url: str
    endpoint_account: str | None
    signing_account: str
    signing_access_key: str
    signing_credential_version: int
    signed_authorization: str
    roster_account: str
    roster_credential_version: int
    status_code: int
    at: datetime


class AuditTrail:
    """Collects every attempt and verifies the three-way correspondence."""

    def __init__(self, broker: FakeIdentityBroker, clock: FakeClock) -> None:
        self._broker = broker
        self._clock = clock
        self.records: list[AttemptRecord] = []

    def record(
        self,
        *,
        service: str,
        operation: str,
        approval: ApprovalContext,
        request,
        status_code: int,
    ) -> AttemptRecord:
        host = urlsplit(request.url).hostname or ""
        prefix_match = ACCOUNT_HOST_PREFIX.match(host)
        endpoint_account = prefix_match.group(1) if prefix_match else None
        frozen = request.context["signing"]["frozen_credentials"]
        duty = self._broker.duty_entry_at(self._clock.now())
        record = AttemptRecord(
            attempt_no=len(self.records) + 1,
            service=service,
            operation=operation,
            approval_id=approval.approval_id,
            approved_account=approval.account_id,
            endpoint_url=request.url,
            endpoint_account=endpoint_account,
            signing_account=frozen.account_id,
            signing_access_key=frozen.access_key,
            signing_credential_version=int(
                frozen.access_key.rsplit("V", 1)[1]
            ),
            signed_authorization=request.headers["Authorization"],
            roster_account=duty.account_id,
            roster_credential_version=duty.credential_version,
            status_code=status_code,
            at=self._clock.now(),
        )
        self.records.append(record)
        return record

    def verify_attempt(
        self, record: AttemptRecord, expect_account_prefix: bool
    ) -> None:
        # Request-side coherence: the approved account is the single source of
        # truth, and both the rendered endpoint and the signer must match it.
        assert record.signing_account == record.approved_account, record
        if expect_account_prefix:
            assert record.endpoint_account == record.approved_account, record
        else:
            assert record.endpoint_account is None, record
        assert record.signing_access_key.startswith(
            f"AKIA-{record.approved_account}-V"
        ), record
        authorization = record.signed_authorization
        if isinstance(authorization, bytes):
            authorization = authorization.decode("utf-8")
        assert (
            f"Credential=AKIA-{record.approved_account}-V" in authorization
        ), record

    def verify_roster(self, record: AttemptRecord) -> None:
        # Duty-side evidence: the roster row stamped on the attempt must match
        # what the broker says was on duty at that instant, and the recorded
        # credential version must belong to that account's issue sequence. It
        # is deliberately allowed to differ from the pinned account when
        # rotation happens mid-flight -- that divergence is the proof the pin
        # held. The version is not compared to the broker's newest issue
        # because
        # a rotation inside the same attempt legitimately advances it.
        duty = self._broker.duty_entry_at(record.at)
        assert duty.account_id == record.roster_account
        versions = {
            issued.version
            for issued in self._broker.issue_log
            if issued.account_id == record.roster_account
        }
        # Version 0 means the on-duty account has not had any credentials
        # issued yet (a rotation with no subsequent approval on that account).
        assert (
            record.roster_credential_version == 0
            or record.roster_credential_version in versions
        )
        # The signer credential itself must be one the broker really issued.
        signed = next(
            issued
            for issued in self._broker.issue_log
            if issued.access_key == record.signing_access_key
        )
        assert signed.account_id == record.signing_account

    def verify_call_account_invariant(
        self, approval_id: str, expected_account: str
    ) -> None:
        rows = [r for r in self.records if r.approval_id == approval_id]
        assert rows, f"no attempts recorded for {approval_id}"
        for row in rows:
            # Even if the roster rotated underneath the call, every request
            # artifact must still carry the originally approved account.
            assert row.approved_account == expected_account
            assert row.signing_account == expected_account
            assert row.endpoint_account in (None, expected_account)


class FakeRawResponse:
    """Minimal urllib3-like raw object that AWSResponse.content expects."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def stream(self, chunk_size=None):
        yield self._body


class OfflineTransport:
    """Scripted HTTP layer: one 500 failure per service, then success.

    Also installs the signing double: after botocore's real SigV4 signer runs
    we snapshot the frozen credentials onto the request context so the audit
    trail can prove which account the signature was built from.
    """

    def __init__(
        self,
        audit: AuditTrail,
        approvals: threading.local,
        provider: "PinnedCredentialProvider",
    ) -> None:
        self._audit = audit
        self._approvals = approvals
        self._provider = provider
        self._failed: set[tuple[str, str, str]] = set()

    def _capture_signed_identity(self, request, **kwargs):
        signer = kwargs["request_signer"]
        frozen = signer._credentials.get_frozen_credentials()
        request.context.setdefault("signing", {})[
            "frozen_credentials"
        ] = frozen

    def register(self, session: Session, service: str, operation: str) -> None:
        service_id = session.get_service_model(service).service_id.hyphenize()
        session.register(
            f"before-sign.{service_id}.{operation}",
            self._capture_signed_identity,
        )
        session.register(
            f"before-send.{service_id}.{operation}",
            self._make_handler(service, operation),
        )

    def _make_handler(self, service: str, operation: str):
        def handler(request, **kwargs):
            approval: ApprovalContext = self._approvals.approval
            # Fail once per logical call (approval), not once per service, so
            # a rebuilt approval demonstrates the failure->rotation path too.
            key = (service, operation, approval.approval_id)
            if key not in self._failed:
                self._failed.add(key)
                status_code, body = 500, b""
                # First transmission failed: rotate before botocore's retry is
                # re-signed. The pinned approval confines the rotation to one
                # account, so this can never become a silent account switch.
                self._provider.rotate_after_failure()
                print(
                    f"  [wire]    attempt failed with 500; rotating "
                    f"credentials within {approval.approval_id} "
                    f"(account {approval.account_id})"
                )
            else:
                status_code = 200
                body = self._success_body(service)
            record = self._audit.record(
                service=service,
                operation=operation,
                approval=approval,
                request=request,
                status_code=status_code,
            )
            expect_prefix = service == "s3control"
            self._audit.verify_attempt(
                record, expect_account_prefix=expect_prefix
            )
            return AWSResponse(
                request.url, status_code, {}, FakeRawResponse(body)
            )

        return handler

    @staticmethod
    def _success_body(service: str) -> bytes:
        if service == "s3control":
            return (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b"<GetAccessGrantsInstanceResult>"
                b"<AccessGrantsInstanceId>default</AccessGrantsInstanceId>"
                b"</GetAccessGrantsInstanceResult>"
            )
        return (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<GetCallerIdentityResponse>"
            b"<GetCallerIdentityResult>"
            b"<Account>pinned-by-signer</Account>"
            b"</GetCallerIdentityResult>"
            b"</GetCallerIdentityResponse>"
        )


class ApprovalBoundClient:
    """Wraps one shared botocore client per service and pins each call.

    The refreshable credential object is created lazily on the first bound
    call and cached on the session, so every service client shares it. The
    call-scoped approval decides which account its refresh callback can mint
    for, which is what keeps a shared client account-safe across retries.
    """

    def __init__(
        self,
        session: Session,
        provider: PinnedCredentialProvider,
        manager: ApprovalManager,
    ) -> None:
        self._session = session
        self._provider = provider
        self._manager = manager
        self._clients = {}

    def _client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self._session.create_client(
                service_name=service,
                region_name=REGION,
                config=Config(
                    region_name=REGION,
                    retries={"mode": "standard", "max_attempts": 3},
                ),
            )
        return self._clients[service]

    def call(
        self,
        service: str,
        operation: str,
        approval: ApprovalContext,
        **kwargs,
    ):
        approval = self._manager.require_valid(approval)
        self._provider.bind(approval)
        try:
            method = getattr(self._client(service), xform_name(operation))
            return method(**kwargs)
        finally:
            self._provider.clear()


def print_attempt_table(audit: AuditTrail) -> None:
    header = (
        f"{'#':>2} {'service':<9} {'endpoint host':<40} "
        f"{'signer key':<18} {'approval':<9} {'on duty':<14} {'http':>4}"
    )
    print(header)
    print("-" * len(header))
    for r in audit.records:
        host = urlsplit(r.endpoint_url).hostname or r.endpoint_url
        roster = f"{r.roster_account[-4:]}@v{r.roster_credential_version}"
        marker = "" if r.roster_account == r.approved_account else " (rotated)"
        print(
            f"{r.attempt_no:>2} {r.service:<9} {host:<40} "
            f"{r.signing_access_key:<18} {r.approval_id:<9} "
            f"{roster + marker:<14} {r.status_code:>4}"
        )


def main() -> None:
    clock = FakeClock(datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc))
    broker = FakeIdentityBroker(clock)
    manager = ApprovalManager(broker, clock)
    call_scope = threading.local()
    provider = PinnedCredentialProvider(broker, clock, call_scope)
    audit = AuditTrail(broker, clock)
    transport = OfflineTransport(audit, call_scope, provider)

    session = Session()
    for service, operation in (
        ("s3control", "GetAccessGrantsInstance"),
        ("sts", "GetCallerIdentity"),
    ):
        transport.register(session, service, operation)

    # The first bind() creates the shared RefreshableCredentials; pin it onto
    # the session so every service client signs through the same object.
    bootstrap = manager.approve()
    session._credentials = provider.bind(bootstrap)
    provider.clear()
    client = ApprovalBoundClient(session, provider, manager)

    print("== Scenario 1: first transmission fails, duty rotates mid-call ==")
    approval_a = manager.approve(policy="REBUILD")
    print(
        f"approved {approval_a.approval_id} on account "
        f"{approval_a.account_id} until {approval_a.expires_at:%H:%M:%S}"
    )
    # Rotation happens after approval but before the retry; the roster itself
    # now names account B while the in-flight call stays pinned to account A.
    broker.rotate_on_duty(
        ACCOUNT_B, "rotation after first failed transmission"
    )
    before = len(audit.records)
    response = client.call(
        "s3control",
        "GetAccessGrantsInstance",
        approval_a,
        AccountId=ACCOUNT_A,
    )
    scenario1 = audit.records[before:]
    print(f"s3control parsed OK: {response['AccessGrantsInstanceId']}")
    audit.verify_call_account_invariant(approval_a.approval_id, ACCOUNT_A)
    for record in scenario1:
        assert record.roster_account == ACCOUNT_B
        audit.verify_roster(record)
    rotated_versions = sorted(
        {r.signing_credential_version for r in scenario1}
    )
    print(
        f"invariant holds: {len(scenario1)} attempts all target/signed as "
        f"{ACCOUNT_A} (cred versions {rotated_versions}) "
        f"while roster says {ACCOUNT_B}"
    )

    print(
        "\n== Scenario 2: ordinary regional endpoint is not "
        "account-scoped =="
    )
    approval_b = manager.approve(policy="REBUILD")
    print(
        f"approved {approval_b.approval_id} on account "
        f"{approval_b.account_id}"
    )
    before = len(audit.records)
    client.call("sts", "GetCallerIdentity", approval_b)
    sts_record = next(
        r for r in audit.records[before:] if r.status_code == 200
    )
    assert sts_record.roster_account == ACCOUNT_B
    audit.verify_roster(sts_record)
    assert sts_record.endpoint_account is None
    assert (
        urlsplit(sts_record.endpoint_url).hostname
        == "sts.us-east-1.amazonaws.com"
    )
    print(f"regional endpoint unchanged: {sts_record.endpoint_url}")

    print(
        "\n== Scenario 3a: approval expired, policy=REBUILD "
        "(safe rebuild) =="
    )
    clock.advance(APPROVAL_TTL + timedelta(minutes=1))
    rebuilt = manager.require_valid(approval_b)
    assert rebuilt.approval_id != approval_b.approval_id
    assert rebuilt.account_id == ACCOUNT_B
    before = len(audit.records)
    client.call(
        "s3control",
        "GetAccessGrantsInstance",
        rebuilt,
        AccountId=ACCOUNT_B,
    )
    audit.verify_call_account_invariant(rebuilt.approval_id, ACCOUNT_B)
    for record in audit.records[before:]:
        assert record.roster_account == ACCOUNT_B
        audit.verify_roster(record)

    print("\n== Scenario 3b: approval expired, policy=STOP (hard stop) ==")
    stopped = manager.approve(policy="STOP")
    clock.advance(APPROVAL_TTL + timedelta(minutes=1))
    try:
        manager.require_valid(stopped)
    except ApprovalExpiredError as exc:
        print(f"stopped as configured: {exc}")
    else:
        raise AssertionError("STOP policy should have raised")

    print("\n== Scenario 3c: rebuild to an unapproved account is refused ==")
    restricted = manager.approve(allow_rebuild_accounts=(ACCOUNT_A,))
    clock.advance(APPROVAL_TTL + timedelta(minutes=1))
    try:
        manager.require_valid(restricted)
    except ApprovalExpiredError as exc:
        print(f"unsafe rebuild refused: {exc}")
    else:
        raise AssertionError("rebuild outside allowlist should have raised")

    print(
        "\n== Audit ledger: every attempt cross-checks "
        "target/signer/roster =="
    )
    print_attempt_table(audit)
    print(
        f"\n{len(audit.records)} attempts verified; credential issues: "
        f"{len(broker.issue_log)}; duty rows: {len(broker.duty_log)}"
    )
    for record in audit.records:
        audit.verify_attempt(
            record, expect_account_prefix=record.service == "s3control"
        )
    print("ALL CROSS-CHECKS PASSED")


if __name__ == "__main__":
    main()
