"""Issuance service tying scope resolution, channel capability and signing.

Strict rule: a channel is only signed when it can express **every** required
condition.  Otherwise the caller gets the structured list of missing
conditions plus the methods that could carry them, and the journal records a
refusal with no signature.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

from minio import Minio
from minio.models import PostPolicy

from .capabilities import (CHANNEL_TITLES, POST_FORM, PUT_URL,
                           available_methods, missing_for_channel)
from .inspector import (ArtifactClaims, VerificationReport, compare_channels,
                        inspect_post_form, inspect_put_url, verify_scope)
from .journal import DENIED, ISSUED, REFUSED, SignatureJournal
from .model import Approval, ScopeConflict, UploadRequest, resolve_scope

SYNTHETIC_ENDPOINT = "127.0.0.1:9000"
SYNTHETIC_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
SYNTHETIC_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SYNTHETIC_REGION = "us-east-1"


@dataclass
class IssueOutcome:
    request_id: str
    channel: str
    status: str
    available_methods: list[str] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    message: str = ""
    scope: Optional[dict] = None
    artifact: Optional[dict] = None
    verification: Optional[dict] = None
    journal_seq: Optional[int] = None

    @property
    def issued(self) -> bool:
        return self.status == ISSUED

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "channel": self.channel,
            "channel_title": CHANNEL_TITLES.get(self.channel, self.channel),
            "status": self.status,
            "issued": self.issued,
            "available_methods": self.available_methods,
            "missing": self.missing,
            "message": self.message,
            "scope": self.scope,
            "artifact": self.artifact,
            "verification": self.verification,
            "journal_seq": self.journal_seq,
        }


class GrantIssuer:
    """Issue minimum-privilege upload credentials with a signature journal."""

    def __init__(
            self,
            client: Any,
            journal: SignatureJournal,
            *,
            public_base_url: str = "http://127.0.0.1:9000",
            endpoint: str = SYNTHETIC_ENDPOINT,
            access_key: str = SYNTHETIC_ACCESS_KEY,
            region: str = SYNTHETIC_REGION,
    ):
        self.client = client
        self.journal = journal
        self.public_base_url = public_base_url.rstrip("/")
        self.endpoint = endpoint
        self.access_key = access_key
        self.region = region

    @classmethod
    def synthetic(
            cls, journal_path: str | Path,
    ) -> "GrantIssuer":
        """Create a fully offline issuer with well-known fake credentials."""
        client = Minio(
            endpoint=SYNTHETIC_ENDPOINT,
            access_key=SYNTHETIC_ACCESS_KEY,
            secret_key=SYNTHETIC_SECRET_KEY,
            secure=False,
            region=SYNTHETIC_REGION,
        )
        return cls(
            client,
            SignatureJournal(journal_path),
            public_base_url=f"http://{SYNTHETIC_ENDPOINT}",
        )

    def issue(
            self,
            request: UploadRequest,
            approval: Approval,
            channel: str,
    ) -> IssueOutcome:
        """Issue one channel, or return the missing-condition report."""
        try:
            scope = resolve_scope(request, approval)
        except ScopeConflict as error:
            record = self.journal.append(
                event=DENIED,
                signed=False,
                request_id=request.request_id,
                approval_id=approval.approval_id,
                channel=channel,
                reason="scope_conflict",
                error=str(error),
                endpoint=self.endpoint,
                access_key=self.access_key,
            )
            return IssueOutcome(
                request_id=request.request_id,
                channel=channel,
                status=DENIED,
                message=str(error),
                journal_seq=record["seq"],
            )

        scope_snapshot = scope.snapshot()
        missing = missing_for_channel(scope, channel)
        methods = available_methods(scope)

        if missing:
            missing_dicts = [item.as_dict() for item in missing]
            message = (
                f"{CHANNEL_TITLES[channel]} 无法表达 "
                + "、".join(item.condition for item in missing)
                + f"；可用发放方式: {', '.join(methods)}"
            )
            record = self.journal.append(
                event=REFUSED,
                signed=False,
                request_id=request.request_id,
                approval_id=approval.approval_id,
                channel=channel,
                reason="missing_conditions",
                missing=missing_dicts,
                available_methods=methods,
                scope=scope_snapshot,
                endpoint=self.endpoint,
                access_key=self.access_key,
            )
            return IssueOutcome(
                request_id=request.request_id,
                channel=channel,
                status="unexpressible",
                available_methods=methods,
                missing=missing_dicts,
                message=message,
                scope=scope_snapshot,
                journal_seq=record["seq"],
            )

        if channel == POST_FORM:
            return self._issue_post(scope, request, approval, methods)
        return self._issue_put(scope, request, approval, methods)

    def _issue_post(
            self, scope, request: UploadRequest, approval: Approval,
            methods: list[str],
    ) -> IssueOutcome:
        policy = PostPolicy(scope.bucket, scope.expires_at)
        if scope.key is not None:
            policy.add_equals_condition("key", scope.key)
        else:
            policy.add_starts_with_condition("key", scope.key_prefix)
        if scope.size_range is not None:
            policy.add_content_length_range_condition(
                scope.size_range.min_bytes, scope.size_range.max_bytes,
            )
        if scope.tags:
            policy.add_equals_condition(
                "x-amz-tagging", scope.tagging_value,
            )

        form_data = self.client.presigned_post_policy(policy)
        post_url = f"{self.public_base_url}/{scope.bucket}"
        claims = inspect_post_form(post_url, form_data)
        report = verify_scope(scope, claims)
        return self._finalize(
            scope, request, approval, POST_FORM, methods,
            artifact={
                "post_url": post_url,
                "form_data": form_data,
                "curl_hint": self._curl_hint(post_url, form_data, scope),
            },
            claims=claims,
            report=report,
        )

    def _issue_put(
            self, scope, request: UploadRequest, approval: Approval,
            methods: list[str],
    ) -> IssueOutcome:
        url = self.client.presigned_put_object(
            bucket_name=scope.bucket,
            object_name=scope.key,
            expires=timedelta(seconds=scope.ttl_seconds),
        )
        claims = inspect_put_url(url)
        report = verify_scope(scope, claims)
        return self._finalize(
            scope, request, approval, PUT_URL, methods,
            artifact={"put_url": url},
            claims=claims,
            report=report,
        )

    def _finalize(
            self, scope, request, approval, channel, methods,
            *, artifact: dict, claims: ArtifactClaims,
            report: VerificationReport,
    ) -> IssueOutcome:
        status = ISSUED if report.consistent else "verification_failed"
        record = self.journal.append(
            event=status,
            signed=True,
            request_id=request.request_id,
            approval_id=approval.approval_id,
            channel=channel,
            available_methods=methods,
            scope=scope.snapshot(),
            artifact=artifact,
            signature=claims.signature,
            credential=claims.credential,
            signed_headers=claims.signed_headers,
            verification=report.as_dict(),
            endpoint=self.endpoint,
            access_key=self.access_key,
        )
        message = (
            "签发成功，产物逐项核对与登记范围一致"
            if report.consistent
            else "签发产物与登记范围核对不一致，已在记录中标记"
        )
        return IssueOutcome(
            request_id=request.request_id,
            channel=channel,
            status=status,
            available_methods=methods,
            message=message,
            scope=scope.snapshot(),
            artifact=artifact,
            verification=report.as_dict(),
            journal_seq=record["seq"],
        )

    @staticmethod
    def _curl_hint(url: str, form_data: dict, scope) -> str:
        fields = " ".join(f"-F {key}=<value>" for key in form_data)
        key_hint = scope.key or f"{scope.key_prefix}<object>"
        return (
            f"curl -X POST {url} {fields} "
            f"-F key={key_hint} -F file=@<FILE>"
        )

    def issue_both(
            self, request: UploadRequest, approval: Approval,
    ) -> tuple[IssueOutcome, IssueOutcome, Optional[dict]]:
        """Issue both channels and cross-check their expressed scope."""
        form_outcome = self.issue(request, approval, POST_FORM)
        put_outcome = self.issue(request, approval, PUT_URL)
        cross: Optional[dict] = None
        if form_outcome.issued and put_outcome.issued:
            form_claims = inspect_post_form(
                form_outcome.artifact["post_url"],
                form_outcome.artifact["form_data"],
            )
            put_claims = inspect_put_url(put_outcome.artifact["put_url"])
            cross = compare_channels(form_claims, put_claims).as_dict()
        return form_outcome, put_outcome, cross
