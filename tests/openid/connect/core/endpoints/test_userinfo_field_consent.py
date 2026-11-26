# -*- coding: utf-8 -*-
"""Per-client field consent narrowing for the UserInfo endpoint.

Two logins can share the same scopes while the resource owner approved a
different subset of profile fields for each partner. The claim producer keeps
returning the same candidate profile; the endpoint narrows the actual HTTP
response to the current client's consent. Scope-only validators that do not
expose consent keep receiving the legacy, unfiltered behaviour.
"""
import json
from unittest import mock

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.openid import RequestValidator, UserInfoEndpoint

from tests.unittest import TestCase


PROFILE = {
    "sub": "employee-7",
    "name": "Li",
    "email": "li@partner.example",
    "phone_number": "139-0000",
    "employee_id": "E-7",
    "salary_band": "P9",
}


def _set_bearer(request, client):
    request.scopes = ["openid", "profile"]
    request.client_id = client


class UserInfoFieldConsentTest(TestCase):

    def _endpoint(self, grants=None, consent_location="hook"):
        validator = RequestValidator()

        def validate_bearer(token, scopes, request):
            client = request.headers.get("X-Partner", "a")
            _set_bearer(request, client)
            if consent_location == "attribute" and grants is not None:
                request.field_consent = grants[client]
            return True

        validator.validate_bearer_token = mock.Mock(
            side_effect=validate_bearer
        )
        validator.get_userinfo_claims = mock.Mock(
            return_value=dict(PROFILE)
        )
        if consent_location == "hook" and grants is not None:
            validator.get_userinfo_allowed_claims = mock.Mock(
                side_effect=lambda request: grants[request.client_id]
            )
        return UserInfoEndpoint(validator), validator

    def _call(self, endpoint, partner):
        return endpoint.create_userinfo_response(
            "https://idp.example/userinfo",
            headers={
                "Authorization": "Bearer token",
                "X-Partner": partner,
            },
        )

    def test_two_partners_same_scope_receive_different_fields(self):
        grants = {
            "a": ["name", "email"],
            "b": ["phone_number", "employee_id"],
        }
        endpoint, validator = self._endpoint(grants)

        headers_a, body_a, status_a = self._call(endpoint, "a")
        headers_b, body_b, status_b = self._call(endpoint, "b")
        claims_a = json.loads(body_a)
        claims_b = json.loads(body_b)

        self.assertEqual(200, status_a)
        self.assertEqual(200, status_b)
        self.assertEqual("application/json", headers_a["Content-Type"])
        self.assertEqual("application/json", headers_b["Content-Type"])
        # The same claim candidates were produced for both logins.
        self.assertEqual(2, validator.get_userinfo_claims.call_count)

        # Core identity claim is always retained.
        self.assertEqual("employee-7", claims_a["sub"])
        self.assertEqual("employee-7", claims_b["sub"])

        # Partner a only sees its approved fields.
        self.assertIn("email", claims_a)
        self.assertIn("name", claims_a)
        self.assertNotIn("phone_number", claims_a)
        self.assertNotIn("employee_id", claims_a)
        self.assertNotIn("salary_band", claims_a)

        # Partner b only sees its own approved fields.
        self.assertIn("phone_number", claims_b)
        self.assertIn("employee_id", claims_b)
        self.assertNotIn("email", claims_b)
        self.assertNotIn("name", claims_b)
        self.assertNotIn("salary_band", claims_b)

    def test_consent_may_be_provided_as_request_attribute(self):
        grants = {
            "a": ["email"],
            "b": ["phone_number"],
        }
        endpoint, _ = self._endpoint(grants, consent_location="attribute")

        _, body_a, _ = self._call(endpoint, "a")
        _, body_b, _ = self._call(endpoint, "b")

        self.assertEqual(
            {"sub": "employee-7", "email": "li@partner.example"},
            json.loads(body_a),
        )
        self.assertEqual(
            {"sub": "employee-7", "phone_number": "139-0000"},
            json.loads(body_b),
        )

    def test_grant_without_evidence_is_classified_without_profile_leak(self):
        grants = {
            "a": [{"field": "salary_band", "evidence": None}],
        }
        endpoint, validator = self._endpoint(grants)

        with self.assertRaises(errors.OAuth2Error) as context:
            self._call(endpoint, "a")

        self.assertIsInstance(
            context.exception,
            (errors.ConsentRequired, errors.InsufficientScopeError),
        )
        error_blob = json.dumps(context.exception.json)
        self.assertNotIn("P9", error_blob)
        self.assertNotIn("salary_band", error_blob)
        # Claim producer is not invoked for an unverified grant.
        validator.get_userinfo_claims.assert_not_called()

    def test_authentication_precedes_consent(self):
        grants = {"a": ["email"]}
        endpoint, validator = self._endpoint(grants)
        validator.validate_bearer_token = mock.Mock(return_value=False)

        with self.assertRaises(errors.InvalidTokenError):
            endpoint.create_userinfo_response(
                "https://idp.example/userinfo",
                headers={"Authorization": "Bearer bad"},
            )

        validator.get_userinfo_allowed_claims.assert_not_called()
        validator.get_userinfo_claims.assert_not_called()


class LegacyScopeOnlyValidator(RequestValidator):

    def validate_bearer_token(self, token, scopes, request):
        request.scopes = ["openid"]
        return True

    def get_userinfo_claims(self, request):
        return dict(PROFILE)


class LegacyIntegrationControlTest(TestCase):

    def test_original_interface_returns_all_produced_claims(self):
        endpoint = UserInfoEndpoint(LegacyScopeOnlyValidator())
        headers, body, status = endpoint.create_userinfo_response(
            "https://idp.example/userinfo",
            headers={"Authorization": "Bearer token"},
        )

        self.assertEqual(200, status)
        self.assertEqual("application/json", headers["Content-Type"])
        self.assertEqual(PROFILE, json.loads(body))
