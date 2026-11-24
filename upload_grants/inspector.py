"""Read back public issuance output and compare it with the grant scope.

Nothing here trusts the issuer's own bookkeeping: the POST policy is base64
decoded from the form field and the PUT claims are parsed from the signed
URL query string.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

from .model import GrantScope, SizeRange, canonical_tags


@dataclass
class ArtifactClaims:
    """Conditions recoverable from an issued credential."""

    channel: str
    bucket: Optional[str] = None
    key: Optional[str] = None
    key_prefix: Optional[str] = None
    size_range: Optional[SizeRange] = None
    tags: dict[str, str] = field(default_factory=dict)
    ttl_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    signature: Optional[str] = None
    credential: Optional[str] = None
    signed_headers: Optional[str] = None
    post_url: Optional[str] = None
    put_url: Optional[str] = None
    form_data: Optional[dict[str, str]] = None
    policy_document: Optional[dict] = None


def _parse_amz_date(value: str) -> datetime:
    return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc,
    )


def inspect_post_form(
        post_url: str, form_data: dict[str, str],
) -> ArtifactClaims:
    """Decode a presigned POST form result."""
    policy_b64 = form_data["policy"]
    policy = json.loads(base64.b64decode(policy_b64).decode("utf-8"))

    claims = ArtifactClaims(
        channel="post_form",
        signature=form_data.get("x-amz-signature"),
        credential=form_data.get("x-amz-credential"),
        post_url=post_url,
        form_data=dict(form_data),
        policy_document=policy,
    )
    claims.expires_at = datetime.strptime(
        policy["expiration"], "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    amz_date = form_data.get("x-amz-date")
    if amz_date:
        signed_at = _parse_amz_date(amz_date)
        claims.ttl_seconds = int(
            (claims.expires_at - signed_at).total_seconds(),
        )

    for condition in policy.get("conditions", []):
        kind = condition[0]
        if kind == "eq":
            element = condition[1].lstrip("$")
            value = condition[2]
            if element == "bucket":
                claims.bucket = value
            elif element == "key":
                claims.key = value
            elif element == "x-amz-tagging":
                claims.tags = _parse_tagging(value)
        elif kind == "starts-with":
            element = condition[1].lstrip("$")
            value = condition[2]
            if element == "key":
                claims.key_prefix = value
        elif kind == "content-length-range":
            claims.size_range = SizeRange(int(condition[1]), int(condition[2]))
    return claims


def _parse_tagging(value: str) -> dict[str, str]:
    parsed = parse_qs(value, keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items()}


def inspect_put_url(url: str) -> ArtifactClaims:
    """Parse claims embedded in a query-presigned PUT URL."""
    parts = urlsplit(url)
    query = parse_qs(parts.query)

    def first(name: str) -> Optional[str]:
        values = query.get(name)
        return values[0] if values else None

    expires_raw = first("X-Amz-Expires")
    ttl_seconds = int(expires_raw) if expires_raw else None
    claims = ArtifactClaims(
        channel="put_url",
        signature=first("X-Amz-Signature"),
        credential=first("X-Amz-Credential"),
        signed_headers=first("X-Amz-SignedHeaders"),
        ttl_seconds=ttl_seconds,
        put_url=url,
    )
    amz_date = first("X-Amz-Date")
    if amz_date and claims.ttl_seconds is not None:
        claims.expires_at = _parse_amz_date(amz_date) + timedelta(
            seconds=claims.ttl_seconds,
        )

    path = unquote(parts.path)
    segments = [segment for segment in path.split("/") if segment]
    if segments:
        claims.bucket = segments[0]
        if len(segments) > 1:
            claims.key = "/".join(segments[1:])
    host_bucket = parts.netloc.split(":")[0].split(".")[0]
    if not claims.bucket and host_bucket:
        claims.bucket = host_bucket
        if segments:
            claims.key = "/".join(segments)
    return claims


@dataclass
class CheckResult:
    name: str
    ok: bool
    expected: object
    actual: object

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass
class VerificationReport:
    consistent: bool
    checks: list[CheckResult]

    def as_dict(self) -> dict:
        return {
            "consistent": self.consistent,
            "checks": [check.as_dict() for check in self.checks],
        }


def _check(name: str, expected: object, actual: object) -> CheckResult:
    return CheckResult(name, expected == actual, expected, actual)


def verify_scope(
        scope: GrantScope, claims: ArtifactClaims,
        *, expiry_skew_seconds: int = 120,
) -> VerificationReport:
    """Compare artifact claims one by one with the registered scope."""
    checks: list[CheckResult] = [
        _check("bucket", scope.bucket, claims.bucket),
    ]

    if scope.key is not None:
        checks.append(_check("target_object", scope.key, claims.key))
    if scope.key_prefix is not None:
        checks.append(
            _check("key_prefix", scope.key_prefix, claims.key_prefix),
        )
    if scope.size_range is not None:
        checks.append(
            _check(
                "content_length_range",
                [scope.size_range.min_bytes, scope.size_range.max_bytes],
                (
                    [claims.size_range.min_bytes, claims.size_range.max_bytes]
                    if claims.size_range else None
                ),
            ),
        )
    if scope.tags:
        checks.append(
            _check("tags", dict(scope.tags), dict(claims.tags)),
        )
        checks.append(
            _check(
                "x-amz-tagging-condition",
                canonical_tags(scope.tags),
                canonical_tags(claims.tags) if claims.tags else None,
            ),
        )

    # A POST policy encodes validity as the exact absolute
    # ``expiration``; a presigned URL encodes it as exact
    # ``X-Amz-Expires`` seconds plus ``X-Amz-Date``.  The POST TTL derived
    # from expiration minus x-amz-date has one-second display rounding.
    if claims.ttl_seconds is not None:
        ttl_drift = abs(scope.ttl_seconds - claims.ttl_seconds)
        ttl_tolerance = 1 if claims.channel == "post_form" else 0
        checks.append(
            CheckResult(
                "ttl_seconds",
                ttl_drift <= ttl_tolerance,
                scope.ttl_seconds,
                claims.ttl_seconds,
            ),
        )

    if claims.expires_at is not None:
        drift = abs(
            (claims.expires_at - scope.expires_at).total_seconds(),
        )
        checks.append(
            CheckResult(
                "expires_at",
                drift <= expiry_skew_seconds,
                scope.expires_at.isoformat(),
                claims.expires_at.isoformat(),
            ),
        )

    if not claims.signature:
        checks.append(
            CheckResult("signature_present", False, "hex signature", None),
        )
    else:
        checks.append(
            CheckResult(
                "signature_present",
                len(claims.signature) == 64
                and all(c in "0123456789abcdef" for c in claims.signature),
                "64-char hex HMAC-SHA256",
                claims.signature[:16] + "...",
            ),
        )

    return VerificationReport(all(check.ok for check in checks), checks)


def compare_channels(
        form_claims: ArtifactClaims,
        put_claims: ArtifactClaims,
) -> VerificationReport:
    """Cross-check the scope expressed by the two issuance outputs."""
    checks = [
        _check("same_bucket", form_claims.bucket, put_claims.bucket),
        _check("same_target_object", form_claims.key, put_claims.key),
    ]
    form_ttl = form_claims.ttl_seconds
    put_ttl = put_claims.ttl_seconds
    ttl_ok = (
        form_ttl is not None and put_ttl is not None
        and abs(form_ttl - put_ttl) <= 1
    )
    checks.append(
        CheckResult(
            "equivalent_ttl_seconds", ttl_ok, put_ttl, form_ttl,
        ),
    )
    return VerificationReport(all(check.ok for check in checks), checks)
