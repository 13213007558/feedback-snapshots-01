# Unit tests for the upload-grant minimum-permission contract.

from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from upload_grants.audit import audit_journal
from upload_grants.capabilities import (POST_FORM, PUT_URL, available_methods,
                                        missing_for_channel)
from upload_grants.inspector import (inspect_post_form, inspect_put_url,
                                     verify_scope)
from upload_grants.issuer import GrantIssuer
from upload_grants.journal import SignatureJournal
from upload_grants.model import (Approval, ScopeConflict, SizeRange,
                                 UploadRequest, resolve_scope)
from upload_grants.scenarios import run_two_requests


def _approval(**overrides):
    params = dict(
        approval_id="APR-T",
        bucket="bucket",
        allowed_prefix="arc/customer/",
        max_ttl=timedelta(minutes=30),
    )
    params.update(overrides)
    return Approval(**params)


def _request(**overrides):
    params = dict(
        request_id="REQ-T",
        bucket="bucket",
        object_key="arc/customer/obj.zip",
        ttl=timedelta(minutes=10),
    )
    params.update(overrides)
    return UploadRequest(**params)


class CommonScopeTest(TestCase):
    def test_approval_prefix_tightens_to_exact_object(self):
        scope = resolve_scope(_request(), _approval())
        self.assertEqual(scope.key, "arc/customer/obj.zip")
        self.assertIsNone(scope.key_prefix)
        self.assertEqual(scope.approved_prefix, "arc/customer/")
        self.assertEqual(scope.ttl_seconds, 600)

    def test_object_outside_approval_prefix_denied(self):
        request = _request(object_key="other/obj.zip")
        with self.assertRaises(ScopeConflict):
            resolve_scope(request, _approval())

    def test_bucket_mismatch_denied(self):
        with self.assertRaises(ScopeConflict):
            resolve_scope(_request(bucket="nope"), _approval())

    def test_prefix_intersection_picks_narrower_side(self):
        request = _request(
            object_key=None, key_prefix="arc/customer/2026/",
        )
        scope = resolve_scope(request, _approval())
        self.assertEqual(scope.key_prefix, "arc/customer/2026/")

        request = _request(
            object_key=None, key_prefix="arc/",
        )
        scope = resolve_scope(
            request, _approval(allowed_prefix="arc/customer/specific/"),
        )
        self.assertEqual(scope.key_prefix, "arc/customer/specific/")

    def test_disjoint_prefixes_denied(self):
        request = _request(object_key=None, key_prefix="upload/x/")
        with self.assertRaises(ScopeConflict):
            resolve_scope(request, _approval(allowed_prefix="archive/y/"))

    def test_size_ranges_intersect(self):
        approval = _approval(size_range=SizeRange(0, 10_000))
        request = _request(size_range=SizeRange(100, 4_000))
        scope = resolve_scope(request, approval)
        self.assertEqual(scope.size_range, SizeRange(100, 4_000))

    def test_disjoint_size_ranges_denied(self):
        approval = _approval(size_range=SizeRange(0, 100))
        request = _request(size_range=SizeRange(200, 400))
        with self.assertRaises(ScopeConflict):
            resolve_scope(request, approval)

    def test_tags_merge_and_conflict_denied(self):
        approval = _approval(required_tags={"a": "1"})
        request = _request(tags={"b": "2", "a": "1"})
        scope = resolve_scope(request, approval)
        self.assertEqual(scope.tags, {"a": "1", "b": "2"})

        conflict = _request(tags={"a": "different"})
        with self.assertRaises(ScopeConflict):
            resolve_scope(conflict, approval)

    def test_ttl_capped_by_approval_max(self):
        request = _request(ttl=timedelta(hours=2))
        scope = resolve_scope(
            request, _approval(max_ttl=timedelta(minutes=5)),
        )
        self.assertEqual(scope.ttl_seconds, 300)


class CapabilityTest(TestCase):
    def test_exact_object_and_ttl_expressible_by_both(self):
        scope = resolve_scope(_request(), _approval())
        self.assertEqual(
            available_methods(scope), [POST_FORM, PUT_URL],
        )
        self.assertEqual(missing_for_channel(scope, PUT_URL), [])

    def test_prefix_only_is_missing_for_put(self):
        request = _request(object_key=None, key_prefix="arc/customer/")
        scope = resolve_scope(request, _approval())
        codes = [m.condition for m in missing_for_channel(scope, PUT_URL)]
        self.assertIn("key_prefix", codes)
        self.assertEqual(available_methods(scope), [POST_FORM])

    def test_size_and_tags_are_form_only(self):
        scope = resolve_scope(
            _request(
                size_range=SizeRange(1, 100),
                tags={"classification": "internal"},
            ),
            _approval(
                size_range=SizeRange(0, 1000),
                required_tags={"classification": "internal"},
            ),
        )
        codes = {m.condition for m in missing_for_channel(scope, PUT_URL)}
        self.assertEqual(codes, {"content_length_range", "tags"})
        self.assertEqual(available_methods(scope), [POST_FORM])
        self.assertEqual(missing_for_channel(scope, POST_FORM), [])


class _SpyClient:
    def __init__(self):
        self.put_calls = []
        self.post_calls = []

    def presigned_put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        raise AssertionError("PUT signer must not be called when missing")

    def presigned_post_policy(self, policy):
        self.post_calls.append(policy)
        raise AssertionError("POST signer should not be needed here")


class RefusalDoesNotSignTest(TestCase):
    def test_put_refusal_never_calls_signer(self):
        with TemporaryDirectory() as tmp:
            journal = SignatureJournal(Path(tmp) / "j.jsonl")
            issuer = GrantIssuer(_SpyClient(), journal)
            request = _request(
                request_id="REQ-SPY",
                size_range=SizeRange(1, 100),
                tags={"classification": "internal"},
            )
            approval = _approval(size_range=SizeRange(0, 1000))
            outcome = issuer.issue(request, approval, PUT_URL)

            self.assertEqual(outcome.status, "unexpressible")
            self.assertEqual(
                {m["condition"] for m in outcome.missing},
                {"content_length_range", "tags"},
            )
            self.assertEqual(outcome.available_methods, [POST_FORM])
            self.assertEqual(issuer.client.put_calls, [])
            rows = journal.query(request_id="REQ-SPY")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event"], "refused")
            self.assertFalse(rows[0]["signed"])
            self.assertIsNone(rows[0].get("signature"))


class ArtifactVerificationTest(TestCase):
    def test_put_url_detects_broadened_object(self):
        with TemporaryDirectory() as tmp:
            issuer = GrantIssuer.synthetic(Path(tmp) / "j.jsonl")
            scope = resolve_scope(_request(), _approval())
            outcome = issuer.issue(_request(), _approval(), PUT_URL)
            self.assertTrue(outcome.issued)

            claims = inspect_put_url(outcome.artifact["put_url"])
            self.assertEqual(claims.key, "arc/customer/obj.zip")

            broad = _request(object_key="arc/customer/other.zip")
            broad_scope = resolve_scope(broad, _approval())
            report = verify_scope(broad_scope, claims)
            self.assertFalse(report.consistent)

    def test_post_policy_carries_every_condition(self):
        with TemporaryDirectory() as tmp:
            issuer = GrantIssuer.synthetic(Path(tmp) / "j.jsonl")
            request = _request(
                size_range=SizeRange(10, 100),
                tags={"classification": "internal"},
            )
            approval = _approval(
                size_range=SizeRange(0, 1000),
                required_tags={"retention": "7y"},
            )
            outcome = issuer.issue(request, approval, POST_FORM)
            self.assertTrue(outcome.issued, outcome.message)
            claims = inspect_post_form(
                outcome.artifact["post_url"],
                outcome.artifact["form_data"],
            )
            self.assertEqual(claims.key, "arc/customer/obj.zip")
            self.assertEqual(claims.size_range, SizeRange(10, 100))
            self.assertEqual(
                claims.tags,
                {"classification": "internal", "retention": "7y"},
            )
            self.assertTrue(outcome.verification["consistent"])


class TwoRequestsScenarioTest(TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.journal_path = Path(self._tmp.name) / "records.jsonl"
        self.report = run_two_requests(self.journal_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_request_one_both_channels_issued_and_match(self):
        one = self.report["request_one"]
        self.assertEqual(one["post_form"]["status"], "issued")
        self.assertEqual(one["put_url"]["status"], "issued")
        self.assertTrue(one["cross_channel"]["consistent"])

        put_url = one["put_url"]["artifact"]["put_url"]
        self.assertIn(
            "/internal-archive/customers/huaxin/ledger/"
            "2026/q4-vouchers.zip?",
            put_url,
        )

    def test_request_two_reports_missing_and_only_form_issued(self):
        two = self.report["request_two"]
        self.assertEqual(two["post_form"]["status"], "issued")
        self.assertEqual(two["put_url"]["status"], "unexpressible")
        codes = {m["condition"] for m in two["put_url"]["missing"]}
        self.assertEqual(codes, {"content_length_range", "tags"})
        self.assertEqual(
            two["put_url"]["available_methods"], [POST_FORM],
        )

    def test_journal_has_no_signed_broad_put_for_request_two(self):
        journal = SignatureJournal(self.journal_path)
        self.assertEqual(journal.issued_puts("REQ-059-02"), [])
        put_rows = journal.query(
            request_id="REQ-059-02", channel=PUT_URL,
        )
        self.assertEqual(len(put_rows), 1)
        self.assertEqual(put_rows[0]["event"], "refused")
        self.assertFalse(put_rows[0]["signed"])

        audit = audit_journal(journal)
        self.assertTrue(audit.ok, audit.as_dict())

    def test_journal_never_stores_secret_key(self):
        content = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn(
            "wJalrXUtnFEMI/K7MDENG", content,
        )
