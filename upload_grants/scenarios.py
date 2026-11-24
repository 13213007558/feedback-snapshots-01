"""The two recorded requests used by the local demonstration.

Request 1 tightens an approved prefix down to one object and issues both
expressible outputs (POST form and presigned PUT).

Request 2 additionally requires a size interval and data tags, which only a
POST policy can express; the PUT call must report the missing items and the
available method instead of signing a broadened URL.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from .audit import audit_journal
from .capabilities import POST_FORM, PUT_URL
from .issuer import GrantIssuer
from .journal import SignatureJournal
from .model import Approval, SizeRange, UploadRequest

BUCKET = "internal-archive"

REQUEST_ONE_ID = "REQ-059-01"
REQUEST_TWO_ID = "REQ-059-02"

APPROVAL_ONE_ID = "APR-2026-1124-01"
APPROVAL_TWO_ID = "APR-2026-1124-02"

CUSTOMER_PREFIX = "customers/huaxin/ledger/"
REQUEST_ONE_OBJECT = CUSTOMER_PREFIX + "2026/q4-vouchers.zip"
REQUEST_TWO_OBJECT = CUSTOMER_PREFIX + "2026/q4-evidence-pack.zip"


def request_one() -> tuple[UploadRequest, Approval]:
    """Prefix approval + application for one exact object."""
    approval = Approval(
        approval_id=APPROVAL_ONE_ID,
        bucket=BUCKET,
        allowed_prefix=CUSTOMER_PREFIX,
        max_ttl=timedelta(minutes=30),
    )
    request = UploadRequest(
        request_id=REQUEST_ONE_ID,
        bucket=BUCKET,
        object_key=REQUEST_ONE_OBJECT,
        ttl=timedelta(minutes=15),
    )
    return request, approval


def request_two() -> tuple[UploadRequest, Approval]:
    """Same workflow, now with mandatory size and label constraints."""
    approval = Approval(
        approval_id=APPROVAL_TWO_ID,
        bucket=BUCKET,
        allowed_prefix=CUSTOMER_PREFIX,
        max_ttl=timedelta(minutes=15),
        size_range=SizeRange(
            1 * 1024 ** 2, 5 * 1024 ** 3,
        ),
        required_tags={
            "classification": "internal",
            "retention-class": "archive-7y",
        },
    )
    request = UploadRequest(
        request_id=REQUEST_TWO_ID,
        bucket=BUCKET,
        object_key=REQUEST_TWO_OBJECT,
        size_range=SizeRange(1 * 1024 ** 2, 2 * 1024 ** 3),
        tags={"classification": "internal", "project": "FB-7558"},
        ttl=timedelta(minutes=10),
    )
    return request, approval


def run_two_requests(journal_path: str | Path) -> dict:
    """Execute both requests against a fresh local JSONL record."""
    journal = SignatureJournal(journal_path)
    issuer = GrantIssuer.synthetic(journal.path)

    req1, apr1 = request_one()
    form1, put1, cross1 = issuer.issue_both(req1, apr1)

    req2, apr2 = request_two()
    post2 = issuer.issue(req2, apr2, POST_FORM)
    put2 = issuer.issue(req2, apr2, PUT_URL)

    audit = audit_journal(journal)
    return {
        "journal_path": str(journal.path),
        "request_one": {
            "description": (
                "获准前缀收紧为单个对象，表单与预签 PUT 两种输出对照"
            ),
            "post_form": form1.as_dict(),
            "put_url": put1.as_dict(),
            "cross_channel": cross1,
        },
        "request_two": {
            "description": "继续要求大小区间与数据标签等仅表单可表达限制",
            "post_form": post2.as_dict(),
            "put_url": put2.as_dict(),
        },
        "audit": audit.as_dict(),
        "records": journal.load(),
    }
