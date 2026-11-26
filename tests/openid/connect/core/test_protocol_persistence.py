# -*- coding: utf-8 -*-
"""Protocol semantics must stay bound to the approved authorization grant.

A single client can use both plain OAuth 2.0 and OpenID Connect.  At the
token exchange the framework must honour the protocol elected when the code
was issued -- proven by the scopes persisted with that code -- even if the
client sends different scopes on the token request or the client default
scopes change in between.

Legacy code records that cannot prove their original scopes get an explicit
conservative disposition: they are never upgraded to OIDC (no ``id_token``)
but the plain OAuth exchange can still complete.  A deployment can instead
enforce rejection by raising :class:`InvalidGrantError` from the provenance
lookup.

These tests run both complete flows against the real pre-configured
:class:`oauthlib.openid.Server` with an in-memory validator; no external IdP
is contacted.
"""
import base64
import json
from unittest import mock
from urllib.parse import parse_qsl, urlparse

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.grant_types.authorization_code import (
    AuthorizationCodeGrant,
)
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from oauthlib.openid import RequestValidator, Server

from tests.unittest import TestCase

REDIRECT_URI = 'https://client.example/cb'
CLIENT_ID = 'cid'


def b64url_decode(value):
    padding = '=' * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value + padding).decode('utf-8'))


class MemoryValidator(RequestValidator):
    """Dict-backed validator recording exactly what was approved."""

    def __init__(self, restore_scopes_in_validate_code=True,
                 strict_legacy=False, provide_scope_lookup=True):
        self.codes = {}
        self.default_scopes = ['read']
        self.restore_scopes_in_validate_code = restore_scopes_in_validate_code
        self.strict_legacy = strict_legacy
        self.provide_scope_lookup = provide_scope_lookup

    # ---- client / redirect / scopes ------------------------------------
    def validate_client_id(self, client_id, request, *args, **kwargs):
        return client_id == CLIENT_ID

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return REDIRECT_URI

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        return redirect_uri == REDIRECT_URI

    def validate_response_type(self, client_id, response_type, client,
                               request, *args, **kwargs):
        return 'code' in (response_type or '')

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return list(self.default_scopes)

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        allowed = {'openid', 'profile', 'read', 'write'}
        return bool(scopes) and all(scope in allowed for scope in scopes)

    # ---- authorization code --------------------------------------------
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes[code['code']] = {
            'scopes': list(request.scopes or []),
            'nonce': getattr(request, 'nonce', None),
            'client_id': client_id,
            'redirect_uri': request.redirect_uri,
            'legacy': False,
        }

    def seed_legacy_code(self, code='OLDCODE'):
        # A record written by an older deployment: no scope/protocol data.
        self.codes[code] = {
            'scopes': None,
            'nonce': None,
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'legacy': True,
        }
        return code

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        record = self.codes.get(code)
        if record is None:
            return False
        request.user = 'alice'
        if self.restore_scopes_in_validate_code and record['scopes'] is not None:
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

    # ---- token endpoint client authentication ---------------------------
    def authenticate_client(self, request, *args, **kwargs):
        request.client = type('Client', (), {'client_id': CLIENT_ID})()
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return True

    def save_token(self, token, request, *args, **kwargs):
        self.saved_token = token

    # ---- OIDC provenance -------------------------------------------------
    def get_authorization_code_scopes(self, client_id, code, redirect_uri,
                                      request):
        if not self.provide_scope_lookup:
            # Simulates an OIDC validator that relies solely on
            # validate_code restoring request.scopes from the grant.
            raise NotImplementedError
        record = self.codes.get(code)
        if record is None:
            return None
        if record['scopes'] is None:
            if self.strict_legacy:
                raise InvalidGrantError(
                    description='authorization code predates scope provenance')
            return None
        return list(record['scopes'])

    def get_authorization_code_nonce(self, client_id, code, redirect_uri,
                                     request):
        record = self.codes.get(code)
        return record['nonce'] if record else None

    def validate_user_match(self, *args, **kwargs):
        return True

    def finalize_id_token(self, id_token, token, token_handler, request):
        payload = base64.urlsafe_b64encode(
            json.dumps(id_token, sort_keys=True).encode()).decode().rstrip('=')
        return 'hdr.%s.sig' % payload


class ProtocolPersistenceTest(TestCase):

    def setUp(self):
        self.validator = MemoryValidator()
        self.server = Server(self.validator)

    def authorize(self, scope=None, nonce=None):
        uri = ('https://idp.example/authorize?response_type=code'
               '&client_id=%s'
               '&redirect_uri=https%%3A%%2F%%2Fclient.example%%2Fcb'
               % CLIENT_ID)
        if scope is not None:
            uri += '&scope=' + scope.replace(' ', '+')
        if nonce is not None:
            uri += '&nonce=' + nonce
        headers, _body, status = self.server.create_authorization_response(uri)
        self.assertEqual(status, 302)
        location = headers['Location']
        query = dict(parse_qsl(urlparse(location).query))
        self.assertIn('code', query)
        return query['code']

    def exchange(self, code, body_scope=None, include_redirect=True):
        body = ('grant_type=authorization_code&client_id=%s&code=%s'
                % (CLIENT_ID, code))
        if include_redirect:
            body += '&redirect_uri=https%3A%2F%2Fclient.example%2Fcb'
        if body_scope is not None:
            body += '&scope=' + body_scope.replace(' ', '+')
        headers, raw_body, status = self.server.create_token_response(
            'https://idp.example/token', body=body)
        return status, headers, json.loads(raw_body)

    def id_token_claims(self, token):
        self.assertIn('id_token', token)
        parts = token['id_token'].split('.')
        return b64url_decode(parts[1])

    # ---- the two complete flows with mid-transaction mutation -----------
    def test_oauth_origin_is_not_upgraded_by_injected_openid_scope(self):
        code = self.authorize(scope='read')
        self.assertEqual(self.validator.codes[code]['scopes'], ['read'])

        # Client tampers with the token request, adding openid/profile.
        status, _headers, token = self.exchange(
            code, body_scope='openid profile')

        self.assertEqual(status, 200)
        self.assertIn('access_token', token)
        self.assertNotIn('id_token', token)
        # Issued scopes stay bound to the approved grant, not the injection.
        self.assertNotIn('openid', token.get('scope', ''))
        self.assertEqual(token['scope'], 'read')

    def test_oidc_origin_keeps_id_token_when_openid_removed_at_exchange(self):
        code = self.authorize(scope='openid profile', nonce='nonce-xyz')
        self.assertEqual(
            self.validator.codes[code]['scopes'], ['openid', 'profile'])

        # Client mutates the token request to drop openid.
        status, _headers, token = self.exchange(code, body_scope='read')

        self.assertEqual(status, 200)
        self.assertIn('access_token', token)
        claims = self.id_token_claims(token)
        self.assertEqual(claims['aud'], CLIENT_ID)
        self.assertEqual(claims['nonce'], 'nonce-xyz')
        # The token scopes are the approved OIDC scopes.
        self.assertIn('openid', token['scope'].split(' '))
        self.assertIn('profile', token['scope'].split(' '))

    def test_two_concurrent_codes_of_same_client_keep_their_protocols(self):
        oauth_code = self.authorize(scope='read')
        oidc_code = self.authorize(scope='openid profile', nonce='n2')

        # Cross-mutate each token request toward the opposite protocol.
        oauth_status, _, oauth_token = self.exchange(
            oauth_code, body_scope='openid')
        oidc_status, _, oidc_token = self.exchange(
            oidc_code, body_scope='read write')

        self.assertEqual(oauth_status, 200)
        self.assertNotIn('id_token', oauth_token)

        self.assertEqual(oidc_status, 200)
        claims = self.id_token_claims(oidc_token)
        self.assertEqual(claims['nonce'], 'n2')

    # ---- changed default configuration ----------------------------------
    def test_changed_default_scopes_do_not_upgrade_oauth_grant(self):
        # No scope requested: approved scope is the current default.
        code = self.authorize()
        self.assertEqual(self.validator.codes[code]['scopes'], ['read'])

        # Administrator updates client default config after approval.
        self.validator.default_scopes = ['read', 'openid']

        status, _, token = self.exchange(code)
        self.assertEqual(status, 200)
        self.assertNotIn('id_token', token)
        self.assertEqual(token['scope'], 'read')

    def test_changed_default_scopes_do_not_downgrade_oidc_grant(self):
        self.validator.default_scopes = ['openid', 'profile']
        code = self.authorize()
        self.assertEqual(
            self.validator.codes[code]['scopes'], ['openid', 'profile'])

        # Default config later drops openid.
        self.validator.default_scopes = ['read']

        status, _, token = self.exchange(code)
        self.assertEqual(status, 200)
        self.id_token_claims(token)

    # ---- legacy records without provenance ------------------------------
    def test_legacy_record_completes_as_plain_oauth_without_id_token(self):
        code = self.validator.seed_legacy_code()

        status, _headers, token = self.exchange(code, body_scope='openid')

        self.assertEqual(status, 200)
        self.assertIn('access_token', token)
        self.assertNotIn('id_token', token)

    def test_legacy_record_strict_policy_returns_invalid_grant(self):
        self.validator.strict_legacy = True
        code = self.validator.seed_legacy_code()

        status, _headers, token = self.exchange(code, body_scope='openid')

        self.assertEqual(status, 400)
        self.assertEqual(token['error'], 'invalid_grant')
        self.assertNotIn('id_token', token)
        self.assertNotIn('access_token', token)

    # ---- framework pins provenance even for a sloppy validate_code ------
    def test_provenance_pins_scopes_when_validate_code_omits_them(self):
        validator = MemoryValidator(
            restore_scopes_in_validate_code=False)
        server = Server(validator)
        self.validator = validator
        self.server = server

        oauth_code = self.authorize(scope='read')
        status, _, token = self.exchange(oauth_code, body_scope='openid')
        self.assertEqual(status, 200)
        self.assertNotIn('id_token', token)
        self.assertEqual(token['scope'], 'read')

        oidc_code = self.authorize(scope='openid profile', nonce='n3')
        status, _, token = self.exchange(oidc_code, body_scope='read')
        self.assertEqual(status, 200)
        self.id_token_claims(token)
        self.assertIn('openid', token['scope'].split(' '))

    def test_validate_code_alone_keeps_protocol_under_scope_mutation(self):
        # Validator does not implement get_authorization_code_scopes; it
        # restores approved scopes in validate_code instead. Routing defers
        # the OIDC decision until those scopes are restored.
        validator = MemoryValidator(provide_scope_lookup=False)
        server = Server(validator)
        self.validator = validator
        self.server = server

        oauth_code = self.authorize(scope='read')
        status, _, token = self.exchange(oauth_code, body_scope='openid')
        self.assertEqual(status, 200)
        self.assertIn('access_token', token)
        self.assertNotIn('id_token', token)

        oidc_code = self.authorize(scope='openid profile', nonce='n4')
        status, _, token = self.exchange(oidc_code, body_scope='read')
        self.assertEqual(status, 200)
        self.id_token_claims(token)


class MockProvenanceGrantTest(TestCase):
    """MagicMock validator variant matching the grant unit-test style."""

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'openid')
        self.request.client_id = 'abcdef'
        self.request.code = '1234'
        self.request.response_type = None
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = 'https://a.b/cb'

        self.validator = mock.MagicMock()
        self.validator.get_code_challenge.return_value = None
        self.validator.get_id_token.return_value = 'MOCKED_ID_TOKEN'

        def set_client(request):
            request.client = mock.MagicMock()
            request.client.client_id = request.client_id
            return True

        self.validator.authenticate_client.side_effect = set_client

        def set_scopes(client_id, code, client, request):
            # Mirrors the existing test: copies the *current* request scopes,
            # i.e. does not independently restore stored provenance.
            request.scopes = self.request.scopes
            request.user = 'bob'
            return True

        self.validator.validate_code.side_effect = set_scopes
        self.grant = AuthorizationCodeGrant(request_validator=self.validator)
        self.bearer = BearerToken(self.validator)

    def token_json(self):
        _headers, body, status = self.grant.create_token_response(
            self.request, self.bearer)
        self.assertEqual(status, 200)
        return json.loads(body)

    def test_oidc_provenance_keeps_id_token_despite_scope_downgrade(self):
        self.validator.get_authorization_code_scopes.return_value = (
            'hello', 'openid')
        # Mid-transaction mutation of the live request scopes.
        self.request.scopes = ('hello', 'world')

        token = self.token_json()
        self.assertIn('id_token', token)
        # Scopes are pinned back to the approved provenance.
        self.assertIn('openid', token['scope'])

    def test_oauth_provenance_blocks_id_token_despite_injected_openid(self):
        self.validator.get_authorization_code_scopes.return_value = (
            'hello', 'world')
        self.request.scopes = ('hello', 'world', 'openid')

        token = self.token_json()
        self.assertNotIn('id_token', token)
        self.assertNotIn('openid', token['scope'])

    def test_none_provenance_never_issues_id_token(self):
        self.validator.get_authorization_code_scopes.return_value = None
        self.request.scopes = ('hello', 'openid')

        token = self.token_json()
        self.assertNotIn('id_token', token)
