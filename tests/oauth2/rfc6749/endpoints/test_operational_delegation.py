# -*- coding: utf-8 -*-
"""Business separation of the introspect / revoke operational delegations.

Scenario under test
-------------------
Two fictional projects own tokens: ``orion`` and ``lyra``.  Two internal
callers exist, each holding a *different* operation permission:

* ``support-beacon`` (support tool) may ``introspect`` the tokens of its
  own project ``orion`` only, and only a limited, approved claim set is
  disclosed.
* ``oncall-sentinel`` (on-call service) may ``revoke`` tokens of the
  approved project ``orion`` only.  It has **no** introspection grant.

The tests cross every caller/operation/project combination and verify all
three vantage points requested by the task: validator calls, the actual
HTTP response and the real in-memory storage.  They also remove a current
delegation while leaving the previous client-authentication result intact
as a control, proving an old approval cannot be reused.
"""
import json
from unittest.mock import ANY, MagicMock

from oauthlib.common import urlencode
from oauthlib.oauth2 import IntrospectEndpoint, RevocationEndpoint, RequestValidator

from tests.unittest import TestCase


ORION = 'project-orion'
LYRA = 'project-lyra'

SUPPORT = 'support-beacon'
ONCALL = 'oncall-sentinel'

APPROVED_INTROSPECTION_FIELDS = frozenset(
    {'scope', 'client_id', 'token_type', 'exp', 'iat'}
)


class DelegationAwareValidator(RequestValidator):
    """In-memory token store + live delegation table."""

    def __init__(self):
        self.clients = {
            SUPPORT: 'support-secret',
            ONCALL: 'oncall-secret',
        }
        # Live delegations: client -> operation -> {project: grant}
        # An introspection grant is the approved field set; a revocation
        # grant is ``True``.
        self.delegations = {
            SUPPORT: {
                'introspect': {ORION: APPROVED_INTROSPECTION_FIELDS},
            },
            ONCALL: {
                'revoke': {ORION: True},
            },
        }
        # Real token storage.  Records are retained (marked revoked) so a
        # repeated revocation can still resolve actual ownership.
        self.tokens = {
            'orion-access-token': {
                'project': ORION,
                'token_type': 'access_token',
                'revoked': False,
                'claims': {
                    'scope': 'incidents:read cases:read',
                    'client_id': 'orion-web',
                    'token_type': 'Bearer',
                    'exp': 1893456000,
                    'iat': 1760000000,
                    # Identity / cross-resource fields that are NOT in the
                    # approved introspection field set.
                    'username': 'alice',
                    'sub': 'user-alice',
                    'email': 'alice@orion.example',
                    'aud': 'orion-api',
                    'jti': 'jti-orion-access-1',
                },
            },
            'orion-refresh-token': {
                'project': ORION,
                'token_type': 'refresh_token',
                'revoked': False,
                'claims': {
                    'scope': 'incidents:read',
                    'client_id': 'orion-web',
                    'token_type': 'refresh_token',
                    'username': 'alice',
                    'sub': 'user-alice',
                },
            },
            'lyra-access-token': {
                'project': LYRA,
                'token_type': 'access_token',
                'revoked': False,
                'claims': {
                    'scope': 'ledger:read',
                    'client_id': 'lyra-billing',
                    'token_type': 'Bearer',
                    'exp': 1893456000,
                    'username': 'bob',
                    'sub': 'user-bob',
                    'email': 'bob@lyra.example',
                },
            },
        }

    # -- shared client authentication (unchanged mechanism) -------------
    def client_authentication_required(self, request, *args, **kwargs):
        return True

    def authenticate_client(self, request, *args, **kwargs):
        secret = self.clients.get(request.client_id)
        if secret is None or request.client_secret != secret:
            return False
        request.client = request.client_id
        return True

    # -- actual ownership ------------------------------------------------
    def get_token_project(self, token, token_type_hint, request, *args, **kwargs):
        record = self.tokens.get(token)
        return record['project'] if record is not None else None

    # -- live delegation checks ------------------------------------------
    def validate_introspection_delegation(self, token, token_type_hint, request,
                                          *args, **kwargs):
        record = self.tokens.get(token)
        if record is None or record['revoked']:
            return False
        grants = self.delegations.get(request.client_id, {}).get('introspect', {})
        return grants.get(record['project'], False)

    def validate_revocation_delegation(self, token, token_type_hint, request,
                                       *args, **kwargs):
        record = self.tokens.get(token)
        if record is None:
            return False
        grants = self.delegations.get(request.client_id, {}).get('revoke', {})
        return record['project'] in grants

    # -- real storage operations -----------------------------------------
    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        record = self.tokens.get(token)
        if record is None or record['revoked']:
            return None
        return dict(record['claims'])

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        record = self.tokens.get(token)
        if record is not None:
            record['revoked'] = True


class OperationalDelegationTest(TestCase):

    def setUp(self):
        self.validator = DelegationAwareValidator()
        # A wraps spy executes the real storage/policy logic while also
        # recording every validator call for assertion.
        self.spy = MagicMock(wraps=self.validator)
        self.introspect_endpoint = IntrospectEndpoint(self.spy)
        self.revoke_endpoint = RevocationEndpoint(self.spy)
        self.headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        self.json_headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }

    def _body(self, token, hint='access_token', client=SUPPORT):
        params = [
            ('token', token),
            ('client_id', client),
            ('client_secret', self.validator.clients[client]),
        ]
        if hint is not None:
            params.append(('token_type_hint', hint))
        return urlencode(params)

    def _introspect(self, token, hint='access_token', client=SUPPORT):
        return self.introspect_endpoint.create_introspect_response(
            'https://ops.example/introspect',
            headers=self.headers,
            body=self._body(token, hint, client),
        )

    def _revoke(self, token, hint='access_token', client=ONCALL):
        return self.revoke_endpoint.create_revocation_response(
            'https://ops.example/revoke',
            headers=self.headers,
            body=self._body(token, hint, client),
        )

    # -- introspection ---------------------------------------------------
    def test_support_introspects_own_project_with_projected_fields(self):
        headers, body, status = self._introspect('orion-access-token')

        self.assertEqual(status, 200)
        self.assertEqual(headers, self.json_headers)
        payload = json.loads(body)
        self.assertTrue(payload['active'])
        # Only the approved fields plus the endpoint-managed active claim.
        self.assertEqual(
            set(payload),
            {'active'} | set(APPROVED_INTROSPECTION_FIELDS),
        )
        # Sensitive identity / cross-resource claims are not disclosed.
        for hidden in ('username', 'sub', 'email', 'aud', 'jti'):
            self.assertNotIn(hidden, payload)
        self.assertEqual(payload['scope'], 'incidents:read cases:read')

        self.spy.validate_introspection_delegation.assert_called_once_with(
            'orion-access-token', 'access_token', ANY
        )
        request_seen = self.spy.validate_introspection_delegation.call_args.args[2]
        self.assertEqual(request_seen.client_id, SUPPORT)
        self.assertEqual(request_seen.token_project, ORION)
        self.assertEqual(request_seen.delegation_action, 'introspect')
        self.spy.introspect_token.assert_called_once()

    def test_unpermitted_introspection_uses_normalized_external_response(self):
        # Support tries to locate a token of the other project.
        self.spy.introspect_token.reset_mock()
        headers, body, status = self._introspect(
            'lyra-access-token', client=SUPPORT
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers, self.json_headers)
        self.assertEqual(body, json.dumps({'active': False}))
        self.assertEqual(json.loads(body), {'active': False})

        request_seen = self.spy.validate_introspection_delegation.call_args.args[2]
        self.assertEqual(request_seen.token_project, LYRA)
        # Claims store is never reached for an unauthorized location.
        self.spy.introspect_token.assert_not_called()

        # Unknown token yields the exact same normalized payload, so the
        # response cannot reveal whether a supplied token belongs to
        # another project.
        _, unknown_body, unknown_status = self._introspect(
            'does-not-exist', client=SUPPORT
        )
        self.assertEqual(unknown_status, 200)
        self.assertEqual(unknown_body, body)

        # The on-call identity has no introspection grant at all.
        _, oncall_body, oncall_status = self._introspect(
            'orion-access-token', client=ONCALL
        )
        self.assertEqual(oncall_status, 200)
        self.assertEqual(oncall_body, json.dumps({'active': False}))

    # -- revocation ------------------------------------------------------
    def test_oncall_revokes_approved_project_and_repeats(self):
        self.assertFalse(self.validator.tokens['orion-access-token']['revoked'])

        headers, body, status = self._revoke('orion-access-token')
        self.assertEqual(status, 200)
        self.assertEqual(headers, {})
        self.assertEqual(body, '')
        self.assertTrue(self.validator.tokens['orion-access-token']['revoked'])
        self.spy.revoke_token.assert_called_once_with(
            'orion-access-token', 'access_token', ANY
        )
        request_seen = self.spy.validate_revocation_delegation.call_args.args[2]
        self.assertEqual(request_seen.token_project, ORION)
        self.assertEqual(request_seen.delegation_action, 'revoke')

        # Revocation is repeatable: same 200, still revoked, storage hook
        # runs again (idempotent marking).
        self.spy.revoke_token.reset_mock()
        headers, body, status = self._revoke('orion-access-token')
        self.assertEqual(status, 200)
        self.assertEqual(body, '')
        self.assertTrue(self.validator.tokens['orion-access-token']['revoked'])
        self.spy.revoke_token.assert_called_once()

        # Refresh tokens of the approved project can be revoked too.
        _, _, status = self._revoke('orion-refresh-token', hint='refresh_token')
        self.assertEqual(status, 200)
        self.assertTrue(self.validator.tokens['orion-refresh-token']['revoked'])

    def test_support_cannot_revoke_without_revoke_delegation(self):
        headers, body, status = self._revoke(
            'orion-access-token', client=SUPPORT
        )
        # Externally identical to a successful revocation...
        self.assertEqual(status, 200)
        self.assertEqual(body, '')
        # ...but real storage is untouched and the mutation hook is skipped.
        self.assertFalse(self.validator.tokens['orion-access-token']['revoked'])
        self.spy.revoke_token.assert_not_called()
        self.spy.validate_revocation_delegation.assert_called_once()

    def test_oncall_cannot_revoke_unapproved_project(self):
        _, body, status = self._revoke('lyra-access-token', client=ONCALL)
        self.assertEqual(status, 200)
        self.assertEqual(body, '')
        self.assertFalse(self.validator.tokens['lyra-access-token']['revoked'])
        self.spy.revoke_token.assert_not_called()
        request_seen = self.spy.validate_revocation_delegation.call_args.args[2]
        self.assertEqual(request_seen.token_project, LYRA)

    # -- cross matrix ----------------------------------------------------
    def test_cross_project_permission_matrix(self):
        # (caller, operation, token, externally visible success?, storage changes?)
        cases = [
            (SUPPORT, 'introspect', 'orion-access-token', True, False),
            (SUPPORT, 'introspect', 'lyra-access-token', False, False),
            (ONCALL, 'introspect', 'orion-access-token', False, False),
            (ONCALL, 'introspect', 'lyra-access-token', False, False),
            (SUPPORT, 'revoke', 'orion-refresh-token', True, False),
            (ONCALL, 'revoke', 'orion-refresh-token', True, True),
            (ONCALL, 'revoke', 'lyra-access-token', True, False),
        ]
        for client, operation, token, discloses, mutates in cases:
            with self.subTest(client=client, operation=operation, token=token):
                record = self.validator.tokens[token]
                before = record['revoked']
                if operation == 'introspect':
                    _, body, status = self._introspect(token, client=client)
                    self.assertEqual(status, 200)
                    payload = json.loads(body)
                    if discloses:
                        self.assertTrue(payload['active'])
                        self.assertIn('scope', payload)
                    else:
                        self.assertEqual(payload, {'active': False})
                else:
                    _, body, status = self._revoke(token, client=client)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, '')
                if mutates:
                    self.assertTrue(record['revoked'])
                else:
                    self.assertEqual(record['revoked'], before)

    # -- freshness of delegation vs client authentication ---------------
    def test_removed_delegation_cannot_reuse_stale_authentication_result(self):
        # Control: the on-call client authenticates successfully and its
        # current revoke delegation works.
        _, _, status = self._revoke('orion-refresh-token', client=ONCALL)
        self.assertEqual(status, 200)
        self.assertTrue(self.validator.tokens['orion-refresh-token']['revoked'])

        # Remove the current delegation.  Client credentials are unchanged,
        # so the old client-authentication outcome remains "success".
        del self.validator.delegations[ONCALL]['revoke'][ORION]
        self.assertNotIn(ORION, self.validator.delegations[ONCALL]['revoke'])

        self.spy.revoke_token.reset_mock()
        target = 'orion-access-token'
        self.assertFalse(self.validator.tokens[target]['revoked'])

        _, body, status = self._revoke(target, client=ONCALL)

        # Same normalized external success...
        self.assertEqual(status, 200)
        self.assertEqual(body, '')
        # ...client authentication still ran and passed (not a 401)...
        self.spy.authenticate_client.assert_called()
        authenticated_request = self.spy.authenticate_client.call_args.args[0]
        self.assertEqual(authenticated_request.client_id, ONCALL)
        self.assertEqual(authenticated_request.client, ONCALL)
        # ...yet the missing *current* delegation blocks the mutation.
        self.spy.revoke_token.assert_not_called()
        self.assertFalse(self.validator.tokens[target]['revoked'])

    def test_mock_stale_authentication_return_value_is_not_authorization(self):
        # Explicit control in the existing MagicMock(wraps=...) style: the
        # retained authenticate_client result stays True throughout.
        validator = MagicMock(wraps=RequestValidator())
        validator.client_authentication_required.return_value = True
        validator.authenticate_client.return_value = True
        validator.get_token_project.return_value = ORION
        validator.validate_revocation_delegation.return_value = True
        validator.revoke_token.return_value = None
        endpoint = RevocationEndpoint(validator)

        body = urlencode([
            ('token', 'orion-access-token'),
            ('token_type_hint', 'access_token'),
            ('client_id', ONCALL),
        ])
        _, _, first_status = endpoint.create_revocation_response(
            'https://ops.example/revoke', headers=self.headers, body=body
        )
        self.assertEqual(first_status, 200)
        validator.revoke_token.assert_called_once()

        # Retain the old authentication result untouched as the control.
        retained_auth_result = validator.authenticate_client.return_value
        self.assertIs(retained_auth_result, True)

        # Current delegation is withdrawn; authentication still returns True.
        validator.revoke_token.reset_mock()
        validator.validate_revocation_delegation.return_value = False

        _, _, second_status = endpoint.create_revocation_response(
            'https://ops.example/revoke', headers=self.headers, body=body
        )
        self.assertEqual(second_status, 200)
        self.assertIs(validator.authenticate_client.return_value, True)
        validator.authenticate_client.assert_called()
        validator.validate_revocation_delegation.assert_called()
        validator.revoke_token.assert_not_called()

    def test_request_only_delegation_signature_is_enforced(self):
        # Validators may centralize the policy in ``(request)`` and read
        # the operation/project from the request.
        class RequestShapeValidator(DelegationAwareValidator):
            def validate_revocation_delegation(self, request):
                return request.token_project == ORION and \
                    request.client_id == ONCALL

        inner = RequestShapeValidator()
        spy = MagicMock(wraps=inner)
        endpoint = RevocationEndpoint(spy)
        _, _, status = endpoint.create_revocation_response(
            'https://ops.example/revoke',
            headers=self.headers,
            body=self._body('lyra-access-token', client=ONCALL),
        )
        self.assertEqual(status, 200)
        self.assertFalse(inner.tokens['lyra-access-token']['revoked'])
        spy.revoke_token.assert_not_called()

    # -- shared client authentication ------------------------------------
    def test_both_endpoints_reject_failed_client_authentication(self):
        self.spy.authenticate_client.return_value = False
        self.spy.authenticate_client_id.return_value = False

        i_headers, i_body, i_status = self._introspect('orion-access-token')
        self.assertEqual(i_status, 401)
        self.assertEqual(json.loads(i_body)['error'], 'invalid_client')

        r_headers, r_body, r_status = self._revoke('orion-access-token')
        self.assertEqual(r_status, 401)
        self.assertEqual(json.loads(r_body)['error'], 'invalid_client')

        self.spy.validate_introspection_delegation.assert_not_called()
        self.spy.validate_revocation_delegation.assert_not_called()
        self.spy.introspect_token.assert_not_called()
        self.spy.revoke_token.assert_not_called()
