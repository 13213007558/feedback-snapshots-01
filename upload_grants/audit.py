"""Audit the local signature record for broadening mistakes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .inspector import inspect_put_url
from .journal import SignatureJournal


@dataclass
class AuditReport:
    ok: bool
    checks: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "checks": self.checks}


def audit_journal(journal: SignatureJournal) -> AuditReport:
    """Verify no signed PUT broadens the registered scope.

    Rules:
    * every journaled ``issued`` record passed self-verification;
    * every issued PUT pins an exact object equal to its scope key;
    * no PUT is ever recorded for a scope carrying form-only conditions.
    """
    checks: list[dict] = []
    records = journal.load()

    bad_verification = [
        r.get("seq") for r in records
        if r.get("verification") is not None
        and not (r.get("verification") or {}).get("consistent")
    ]
    checks.append({
        "name": "all_issued_artifacts_match_scope",
        "ok": not bad_verification,
        "bad_seqs": bad_verification,
    })

    broadened: list[int] = []
    form_only_puts: list[int] = []
    signed_puts = [
        r for r in records
        if r.get("channel") == "put_url" and r.get("signed") is True
    ]
    for record in signed_puts:
        scope = record.get("scope") or {}
        has_form_only = (
            scope.get("size_range")
            or scope.get("tags")
            or scope.get("key_prefix")
        )
        if has_form_only:
            form_only_puts.append(record["seq"])
        expected_key = scope.get("key")
        url = ((record.get("artifact") or {}).get("put_url"))
        if not expected_key or not url:
            broadened.append(record["seq"])
            continue
        claims = inspect_put_url(url)
        if claims.key != expected_key:
            broadened.append(record["seq"])

    checks.append({
        "name": "issued_puts_pin_exact_scope_object",
        "ok": not broadened,
        "bad_seqs": broadened,
    })
    checks.append({
        "name": "no_put_signed_with_form_only_conditions",
        "ok": not form_only_puts,
        "bad_seqs": form_only_puts,
    })

    return AuditReport(all(check["ok"] for check in checks), checks)


def assert_request_has_no_issued_put(
        journal: SignatureJournal, request_id: str,
) -> None:
    """Raise AssertionError if the request has any signed PUT record."""
    puts = journal.issued_puts(request_id)
    if puts:
        raise AssertionError(
            f"{request_id} has {len(puts)} issued PUT credential(s), "
            "expected none",
        )
