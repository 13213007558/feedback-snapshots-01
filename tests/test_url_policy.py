from django.test import SimpleTestCase

from storages.url_policy import SignedUrlParameterError
from storages.url_policy import SignedUrlParameterPolicy


class SignedUrlParameterPolicyTests(SimpleTestCase):
    def test_no_allow_list_passes_everything_through(self):
        policy = SignedUrlParameterPolicy()
        self.assertFalse(policy.enforced)
        params = policy.resolve({"anything_goes": "value"})
        self.assertEqual(params, {"anything_goes": "value"})

    def test_allowed_parameters_pass_through(self):
        policy = SignedUrlParameterPolicy(
            allowed_parameters=["content_type", "content_disposition"]
        )
        params = policy.resolve({"content_type": "text/plain"})
        self.assertEqual(params, {"content_type": "text/plain"})

    def test_disallowed_parameter_is_rejected_before_signing(self):
        policy = SignedUrlParameterPolicy(allowed_parameters=["content_type"])
        with self.assertRaises(SignedUrlParameterError) as ctx:
            policy.resolve({"content_type": "text/plain", "evil_param": "x"})
        # Only the offending *name* is exposed; no value or credential leaks.
        message = str(ctx.exception)
        self.assertIn("evil_param", message)
        self.assertNotIn("x", message)

    def test_unknown_alias_is_rejected(self):
        policy = SignedUrlParameterPolicy(allowed_parameters=["content_type"])
        with self.assertRaises(SignedUrlParameterError):
            policy.resolve(alias="does-not-exist")

    def test_alias_defaults_are_applied(self):
        policy = SignedUrlParameterPolicy(
            allowed_parameters=["content_type", "content_disposition"],
            aliases={
                "preview": {"content_type": "application/pdf"},
                "download": {
                    "content_disposition": 'attachment; filename="report.pdf"'
                },
            },
        )
        self.assertEqual(
            policy.resolve(alias="preview"),
            {"content_type": "application/pdf"},
        )
        self.assertEqual(
            policy.resolve(alias="download"),
            {"content_disposition": 'attachment; filename="report.pdf"'},
        )

    def test_caller_parameters_override_alias_defaults(self):
        policy = SignedUrlParameterPolicy(
            allowed_parameters=["content_type"],
            aliases={"preview": {"content_type": "application/pdf"}},
        )
        params = policy.resolve(
            {"content_type": "image/png"}, alias="preview"
        )
        self.assertEqual(params, {"content_type": "image/png"})

    def test_alias_defaults_must_themselves_be_allowed(self):
        with self.assertRaises(SignedUrlParameterError) as ctx:
            SignedUrlParameterPolicy(
                allowed_parameters=["content_type"],
                aliases={"broken": {"not_allowed": "v"}},
            )
        self.assertIn("not_allowed", str(ctx.exception))

    def test_error_message_never_contains_parameter_values(self):
        secret = "super-secret-value-123"
        policy = SignedUrlParameterPolicy(allowed_parameters=["content_type"])
        with self.assertRaises(SignedUrlParameterError) as ctx:
            policy.resolve({"token": secret})
        self.assertNotIn(secret, str(ctx.exception))
