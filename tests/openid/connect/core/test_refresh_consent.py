# -*- coding: utf-8 -*-
"""Incremental withdrawal of per-application OIDC consent.

Two applications of the same group share one OIDC login and one subject
(``alice``).  The resource owner initially approves identity data
(``openid profile``) and an ordinary API (``api:read``) for both.  The owner
then withdraws the identity-data permission for application A only.

Refresh tokens minted *before* the withdrawal remain valid credentials, so
the framework must:

* narrow a default (no ``scope`` parameter) refresh to what A may still use;
* reject an explicit request for the withdrawn scope with ``invalid_scope``;
* stop minting an ID token for A once ``openid`` is withdrawn, and omit
  withdrawn identity claims when only ``profile`` is withdrawn;
* persist, in ``save_bearer_token``, the scopes that were really retained and
  return exactly those scopes in the credential;
* leave application B of the same subject untouched; and
* refuse access to the withdrawn scope at the protected resource, while
  continuing to allow the retained ordinary API.

Everything runs against the real pre-configured ``oauthlib.openid.Server``
with an in-memory validator; no external identity provider is contacted.
"""
import base64
import json
from unittest import mock
from urllib.parse import parse_qsl, urlparse

from oauthlib.common import Request
from oauthlib.oauth2 import RefreshTokenGrant, RequestValidator
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid import Server

from tests.unittest import TestCase

REDIRECT_URI = 'https://rp.example/cb'
SUBJECT = 'alice'
APP_A = 'group-app-a'
APP_B = 'group-app-b'
CLIENTS = {APP_A: 'secret-a', APP_B: 'secret-b'}
FULL_SCOPES = ['openid', 'profile', 'api:read']


def b64url_decode(value):
    padding = '=' * (-len(value) % 4)
    return json.loads(
        base64.urlsafe_b64decode(value + padding).decode('utf-8'))


class ConsentValidator(RequestValidator):
    """In-memory grants plus a live per-client consent table."""

    def __init__(self):
        self.codes = {}
        self.refresh_tokens = {}
        self.access_tokens = {}
        self.saved_tokens = []
        # Current consent: (client_id, subject) -> scope set.
        self.consent = {
            (APP_A, SUBJECT): set(FULL_SCOPES),
            (APP_B, SUBJECT): set(FULL_SCOPES),
        }

    # ---- client / redirect / scopes ------------------------------------
    def validate_client_id(self, client_id, request, *args, **kwargs):
        return client_id in CLIENTS

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return REDIRECT_URI

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        return redirect_uri == REDIRECT_URI

    def validate_response_type(self, client_id, response_type, client,
                               request, *args, **kwargs):
        return 'code' in (response_type or '')

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return list(FULL_SCOPES)

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        return True

    # ---- authorization codes --------------------------------------------
    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        self.codes[code['code']] = {
            'client_id': client_id,
            'user': request.user,
            'scopes': list(request.scopes),
            'nonce': getattr(request, 'nonce', None),
            'redirect_uri': request.redirect_uri,
        }

    def validate_code(self, client_id, code, client, request,
                      *args, **kwargs):
        record = self.codes.get(code)
        if not record:
            return False
        request.user = record['user']
        request.scopes = list(record['scopes'])
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             request, *args, **kwargs):
        record = self.codes.get(code)
        return bool(record) and record['redirect_uri'] == redirect_uri

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        self.codes.pop(code, None)

    def get_code_challenge(self, code, request):
        return None

    def get_authorization_code_scopes(self, client_id, code, redirect_uri,
                                      request):
        record = self.codes.get(code)
        return list(record['scopes']) if record else None

    def get_authorization_code_nonce(self, client_id, code, redirect_uri,
                                     request):
        record = self.codes.get(code)
        return record['nonce'] if record else None

    # ---- token endpoint ---------------------------------------------------
    def authenticate_client(self, request, *args, **kwargs):
        if CLIENTS.get(request.client_id) != request.client_secret:
            return False
        request.client = type(
            'Client', (), {'client_id': request.client_id})()
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return True

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        record = self.refresh_tokens.get(refresh_token)
        client_id = getattr(client, 'client_id', None) or request.client_id
        if not record or record['client_id'] != client_id:
            return False
        request.user = record['user']
        return True

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        record = self.refresh_tokens.get(refresh_token)
        return list(record['scopes']) if record else []

    def get_current_scopes(self, token, token_type_hint, request,
                           *args, **kwargs):
        record = (self.refresh_tokens.get(token)
                  or self.access_tokens.get(token))
        if record is None:
            return None
        consented = self.consent.get((record['client_id'], record['user']))
        return None if consented is None else sorted(consented)

    def save_bearer_token(self, token, request, *args, **kwargs):
        record = {
            'client_id': request.client_id,
            'user': request.user,
            'scopes': list(request.scopes),
        }
        self.saved_tokens.append({
            **record,
            'returned_scope': token.get('scope'),
            'retained_scopes': list(
                getattr(request, 'retained_scopes', []) or []),
            'consented_scopes': list(
                getattr(request, 'consented_scopes', []) or []),
            'original_scopes': list(
                getattr(request, 'original_scopes', []) or []),
            'access_token': token['access_token'],
            'refresh_token': token.get('refresh_token'),
        })
        self.access_tokens[token['access_token']] = dict(record)
        if token.get('refresh_token'):
            self.refresh_tokens[token['refresh_token']] = dict(record)

    # ---- resource validation ---------------------------------------------
    def validate_bearer_token(self, token, scopes, request, *args, **kwargs):
        record = self.access_tokens.get(token)
        if record is None:
            return False
        request.user = record['user']
        request.client_id = record['client_id']
        request.client = type(
            'Client', (), {'client_id': record['client_id']})()
        request.scopes = list(record['scopes'])
        return all(scope in record['scopes'] for scope in (scopes or []))

    # ---- introspection -----------------------------------------------------
    def introspect_token(self, token, token_type_hint, request,
                         *args, **kwargs):
        record = (self.refresh_tokens.get(token)
                  or self.access_tokens.get(token))
        if record is None:
            return None
        return {
            'scope': ' '.join(record['scopes']),
            'client_id': record['client_id'],
            'username': record['user'],
        }

    # ---- OIDC -------------------------------------------------------------
    def validate_user_match(self, *args, **kwargs):
        return True

    def refresh_id_token(self, request):
        return True

    def get_id_token(self, token, token_handler, request):
        return None

    def finalize_id_token(self, id_token, token, token_handler, request):
        id_token.update({
            'iss': 'https://op.example',
            'sub': request.user,
            'exp': id_token['iat'] + 3600,
        })
        if 'profile' in (request.scopes or []):
            id_token['name'] = 'Alice Example'
        payload = base64.urlsafe_b64encode(
            json.dumps(id_token, sort_keys=True).encode()).decode().rstrip('=')
        return 'header.%s.signature' % payload


class RefreshConsentTest(TestCase):

    def setUp(self):
        self.validator = ConsentValidator()
        self.server = Server(self.validator)

    # ---- helpers -----------------------------------------------------------
    def login(self, client_id, subject=SUBJECT):
        uri = (
            'https://op.example/authorize?response_type=code'
            '&client_id=%s'
            '&redirect_uri=https%%3A%%2F%%2Frp.example%%2Fcb'
            '&scope=openid+profile+api%%3Aread'
            '&nonce=nonce-%s' % (client_id, client_id)
        )
        headers, _body, status = self.server.create_authorization_response(uri)
        self.assertEqual(302, status)
        code = dict(parse_qsl(urlparse(headers['Location']).query))['code']
        # The endpoint leaves request.user to the application's login view.
        self.validator.codes[code]['user'] = subject
        return self.exchange_code(client_id, code)

    def exchange_code(self, client_id, code):
        body = (
            'grant_type=authorization_code'
            '&client_id=%s&client_secret=%s&code=%s'
            '&redirect_uri=https%%3A%%2F%%2Frp.example%%2Fcb'
            % (client_id, CLIENTS[client_id], code)
        )
        headers, raw_body, status = self.server.create_token_response(
            'https://op.example/token', body=body)
        self.assertEqual(200, status, raw_body)
        return json.loads(raw_body)

    def refresh(self, client_id, refresh_token, scope=None):
        body = (
            'grant_type=refresh_token'
            '&client_id=%s&client_secret=%s&refresh_token=%s'
            % (client_id, CLIENTS[client_id], refresh_token)
        )
        if scope is not None:
            body += '&scope=' + scope.replace(' ', '+')
        headers, raw_body, status = self.server.create_token_response(
            'https://op.example/token', body=body)
        return status, json.loads(raw_body)

    def resource(self, token, scopes):
        valid, request = self.server.verify_request(
            'https://api.example/resource',
            headers={'Authorization': 'Bearer ' + token},
            scopes=scopes,
        )
        return valid, request

    def withdraw(self, client_id, scope, subject=SUBJECT):
        self.validator.consent[(client_id, subject)].discard(scope)

    @staticmethod
    def id_token_claims(token):
        return b64url_decode(token['id_token'].split('.')[1])

    # ---- the requested scenario -------------------------------------------
    def test_same_subject_two_applications_login_separately(self):
        token_a = self.login(APP_A)
        token_b = self.login(APP_B)

        for token in (token_a, token_b):
            self.assertEqual(set(FULL_SCOPES), set(token['scope'].split()))
            self.assertIn('id_token', token)
            self.assertEqual(
                SUBJECT, self.id_token_claims(token)['sub'])

    def test_withdrawal_narrows_default_refresh_for_that_app_only(self):
        token_a = self.login(APP_A)
        token_b = self.login(APP_B)
        self.withdraw(APP_A, 'profile')

        status_a, refreshed_a = self.refresh(APP_A, token_a['refresh_token'])
        status_b, refreshed_b = self.refresh(APP_B, token_b['refresh_token'])

        self.assertEqual(200, status_a)
        self.assertEqual(200, status_b)
        # A keeps the ordinary API and identity login, without profile.
        self.assertEqual({'openid', 'api:read'},
                         set(refreshed_a['scope'].split()))
        self.assertNotIn('profile', refreshed_a['scope'].split())
        # The refreshed ID token no longer asserts profile identity data.
        claims_a = self.id_token_claims(refreshed_a)
        self.assertNotIn('name', claims_a)
        self.assertEqual(SUBJECT, claims_a['sub'])
        # B, same subject, is untouched.
        self.assertEqual(set(FULL_SCOPES),
                         set(refreshed_b['scope'].split()))
        self.assertEqual('Alice Example',
                         self.id_token_claims(refreshed_b)['name'])

    def test_explicit_retained_scope_succeeds_explicit_withdrawn_fails(self):
        token_a = self.login(APP_A)
        self.withdraw(APP_A, 'profile')

        status, retained = self.refresh(
            APP_A, token_a['refresh_token'], 'openid api:read')
        self.assertEqual(200, status)
        self.assertEqual({'openid', 'api:read'},
                         set(retained['scope'].split()))

        saves_before = len(self.validator.saved_tokens)
        status, rejected = self.refresh(
            APP_A, token_a['refresh_token'], 'openid profile api:read')
        self.assertEqual(400, status)
        self.assertEqual('invalid_scope', rejected['error'])
        self.assertNotIn('access_token', rejected)
        # Nothing was persisted for the rejected request.
        self.assertEqual(saves_before, len(self.validator.saved_tokens))

    def test_withdrawing_openid_stops_id_token_issuance(self):
        token_a = self.login(APP_A)
        self.withdraw(APP_A, 'openid')

        status, refreshed = self.refresh(APP_A, token_a['refresh_token'])
        self.assertEqual(200, status)
        self.assertEqual({'profile', 'api:read'},
                         set(refreshed['scope'].split()))
        # No OIDC audience-restricted credential is left behind.
        self.assertNotIn('id_token', refreshed)

    def test_explicit_scope_cannot_widen_beyond_original_grant(self):
        # The owner is happy to approve ``api:write`` for the client, but the
        # refresh token was never issued for it.  Live consent narrows the
        # grant; it must never widen it.
        token_a = self.login(APP_A)
        self.validator.consent[(APP_A, SUBJECT)].add('api:write')

        status, response = self.refresh(
            APP_A, token_a['refresh_token'], 'openid api:write')
        self.assertEqual(400, status)
        self.assertEqual('invalid_scope', response['error'])

    def test_withdrawing_every_scope_refuses_to_mint_a_token(self):
        token_a = self.login(APP_A)
        for scope in FULL_SCOPES:
            self.withdraw(APP_A, scope)

        status, response = self.refresh(APP_A, token_a['refresh_token'])
        self.assertEqual(400, status)
        self.assertEqual('invalid_scope', response['error'])
        self.assertNotIn('access_token', response)

    def test_persisted_record_matches_returned_credential(self):
        token_a = self.login(APP_A)
        self.withdraw(APP_A, 'profile')
        status, refreshed = self.refresh(APP_A, token_a['refresh_token'])
        self.assertEqual(200, status)

        saved = self.validator.saved_tokens[-1]
        returned_scopes = [
            scope for scope in refreshed['scope'].split() if scope]
        # The persistent evidence records all three views: what the token
        # was originally issued for, what the owner still consents to, and
        # what this credential really retained.
        self.assertEqual(set(FULL_SCOPES),
                         set(saved['original_scopes']))
        self.assertEqual({'openid', 'api:read'},
                         set(saved['consented_scopes']))
        self.assertEqual({'openid', 'api:read'},
                         set(saved['retained_scopes']))
        self.assertEqual(set(saved['retained_scopes']),
                         set(saved['scopes']))
        self.assertEqual(set(returned_scopes),
                         set(saved['scopes']))
        self.assertEqual(' '.join(saved['scopes']),
                         refreshed['scope'])
        # The stored refresh token also carries only the retained scopes.
        stored = self.validator.refresh_tokens[refreshed['refresh_token']]
        self.assertEqual(set(saved['scopes']), set(stored['scopes']))

    def test_resource_validation_uses_current_consent(self):
        token_a = self.login(APP_A)
        token_b = self.login(APP_B)
        # Withdrawal happens after both access tokens were issued.
        self.withdraw(APP_A, 'profile')

        # The pre-withdrawal token keeps the ordinary, retained API.
        valid, request = self.resource(token_a['access_token'], ['api:read'])
        self.assertTrue(valid)
        self.assertEqual({'openid', 'api:read'}, set(request.scopes))

        # The withdrawn permission is refused...
        valid, _ = self.resource(token_a['access_token'], ['profile'])
        self.assertFalse(valid)

        # ...including after a refresh that re-issued the token.
        status, refreshed = self.refresh(APP_A, token_a['refresh_token'])
        self.assertEqual(200, status)
        self.assertFalse(
            self.resource(refreshed['access_token'], ['profile'])[0])
        self.assertTrue(
            self.resource(refreshed['access_token'], ['api:read'])[0])

        # The other application of the same subject is unaffected.
        self.assertTrue(
            self.resource(token_b['access_token'], ['profile'])[0])

    def test_client_parameters_cannot_spoof_consent(self):
        token_a = self.login(APP_A)
        self.withdraw(APP_A, 'profile')
        # A malicious client sends consent-looking parameters.  The framework
        # must use the validator's live consent, not request fields.
        body = (
            'grant_type=refresh_token'
            '&client_id=%s&client_secret=%s&refresh_token=%s'
            '&consented_scopes=openid+profile+api%%3Aread'
            '&retained_scopes=openid+profile+api%%3Aread'
            % (APP_A, CLIENTS[APP_A], token_a['refresh_token'])
        )
        _headers, raw_body, status = self.server.create_token_response(
            'https://op.example/token', body=body)

        self.assertEqual(200, status)
        refreshed = json.loads(raw_body)
        self.assertEqual({'openid', 'api:read'},
                         set(refreshed['scope'].split()))
        self.assertNotIn('profile', refreshed['scope'].split())
        self.assertFalse(
            self.resource(refreshed['access_token'], ['profile'])[0])

    def test_introspection_reports_live_retained_scope(self):
        token_a = self.login(APP_A)
        token_b = self.login(APP_B)
        self.withdraw(APP_A, 'profile')

        _, body_a, status = self.server.create_introspect_response(
            'https://op.example/introspect',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            body='token=%s&token_type_hint=refresh_token'
                 % token_a['refresh_token'],
        )
        _, body_b, _ = self.server.create_introspect_response(
            'https://op.example/introspect',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            body='token=%s&token_type_hint=refresh_token'
                 % token_b['refresh_token'],
        )

        self.assertEqual(200, status)
        self.assertEqual({'openid', 'api:read'},
                         set(json.loads(body_a)['scope'].split()))
        self.assertEqual(set(FULL_SCOPES),
                         set(json.loads(body_b)['scope'].split()))


class ResourceMutationTest(TestCase):
    """Mutating ``request.scopes`` cannot weaken the requirement."""

    def test_in_place_scope_mutation_does_not_bypass_consent(self):
        validator = mock.MagicMock()

        def validate(token, scopes, request):
            # Malicious/sloppy in-place change of the resource requirement.
            scopes.clear()
            request.scopes = ['api:read']
            return True

        validator.validate_bearer_token.side_effect = validate
        validator.get_current_scopes.return_value = ['api:read']
        request = Request(
            'https://api.example/x',
            headers={'Authorization': 'Bearer token'})
        request.scopes = ['profile']

        valid = BearerToken(validator).validate_request(request)

        self.assertFalse(valid)


class LegacyValidatorControlTest(TestCase):
    """A validator without a live-consent hook keeps its old behaviour."""

    def test_refresh_is_unchanged_without_consent_hook(self):
        validator = mock.MagicMock()
        validator.get_original_scopes.return_value = ['openid', 'read']
        validator.validate_refresh_token.return_value = True
        # The default RequestValidator hook answers ``None``; a plain MagicMock
        # answers a mock object, which is also treated as "no live consent".
        validator.get_current_scopes.return_value = None
        request = Request('https://op.example/token')
        request.grant_type = 'refresh_token'
        request.refresh_token = 'rt'
        request.client_id = 'client'
        request.client = mock.MagicMock(client_id='client')
        request.scope = None

        grant = RefreshTokenGrant(validator)
        _headers, body, status = grant.create_token_response(
            request, BearerToken(validator))

        self.assertEqual(200, status)
        self.assertEqual('openid read', json.loads(body)['scope'])
        validator.get_current_scopes.assert_called_once_with(
            'rt', 'refresh_token', request)
