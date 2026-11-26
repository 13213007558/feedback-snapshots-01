from types import SimpleNamespace
from urllib.parse import parse_qs, parse_qsl, urlparse

from oauthlib.common import safe_string_equals
from oauthlib.oauth1 import (
    SIGNATURE_HMAC_SHA256,
    AccessTokenEndpoint,
    AuthorizationEndpoint,
    Client,
    RequestTokenEndpoint,
    RequestValidator,
    ResourceEndpoint,
    SignatureOnlyEndpoint,
)

from tests.unittest import TestCase


CLIENT_KEY = 'partnerclient' + '0' * 17
CLIENT_SECRET = 'synthetic-client-secret'
CALLBACK_URI = 'https://partner.test/oauth1/callback'

REQUEST_TOKEN_URL = 'https://provider.test/oauth1/request-token'
AUTHORIZE_URL = 'https://provider.test/oauth1/authorize'
ACCESS_TOKEN_URL = 'https://provider.test/oauth1/access-token'

REPORTS_SCOPE = 'reports.read'
BILLING_SCOPE = 'billing.read'
REPORTS_RESOURCE_URL = 'https://resources.test/v1/reports'
BILLING_RESOURCE_URL = 'https://resources.test/v1/billing'

DUMMY_CLIENT_KEY = 'dummyclient' + '0' * 19
DUMMY_CLIENT_SECRET = 'dummy-client-secret'
DUMMY_REQUEST_TOKEN = 'dummyrequest' + '0' * 18
DUMMY_REQUEST_SECRET = 'dummy-request-secret'
DUMMY_ACCESS_TOKEN = 'dummyaccesstok' + '0' * 16
DUMMY_ACCESS_SECRET = 'dummy-access-secret'
UNAPPROVED_VERIFIER = '9' * 30


class RecordingGrantValidator(RequestValidator):
    """In-memory provider storage and audit facts for one OAuth1 client."""

    realms = (REPORTS_SCOPE, BILLING_SCOPE)
    allowed_signature_methods = (SIGNATURE_HMAC_SHA256,)
    timestamp_lifetime = 600
    dummy_client = DUMMY_CLIENT_KEY
    dummy_request_token = DUMMY_REQUEST_TOKEN
    dummy_access_token = DUMMY_ACCESS_TOKEN

    def __init__(self):
        super().__init__()
        self.clients = {
            CLIENT_KEY: {
                'secret': CLIENT_SECRET,
                'redirect_uri': CALLBACK_URI,
            },
            DUMMY_CLIENT_KEY: {
                'secret': DUMMY_CLIENT_SECRET,
                'redirect_uri': 'oob',
            },
        }
        self.request_tokens = {}
        self.access_tokens = {}
        self.used_nonces = set()
        self.reads = []
        self.writes = []

    def _read(self, operation, token=None, **facts):
        fact = {'op': operation, 'token': token}
        fact.update(facts)
        self.reads.append(fact)

    def _write(self, operation, token=None, **facts):
        fact = {'op': operation, 'token': token}
        fact.update(facts)
        self.writes.append(fact)

    def operations_for(self, bucket, token):
        return [
            fact['op']
            for fact in getattr(self, bucket)
            if fact.get('token') == token
        ]

    def active_access_grants(self, client_key=None):
        return {
            token: record
            for token, record in self.access_tokens.items()
            if record['status'] == 'active'
            and (client_key is None or record['client_key'] == client_key)
        }

    def validate_client_key(self, client_key, request):
        allowed = client_key in self.clients
        self._read('validate_client_key', client_key=client_key,
                   allowed=allowed)
        return allowed

    def get_client_secret(self, client_key, request):
        client = self.clients.get(client_key)
        self._read('get_client_secret', client_key=client_key,
                   dummy=client is None)
        return client['secret'] if client else DUMMY_CLIENT_SECRET

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        expected = self.clients.get(client_key, {}).get('redirect_uri')
        allowed = redirect_uri == expected
        self._read('validate_redirect_uri', client_key=client_key,
                   allowed=allowed)
        return allowed

    def get_default_realms(self, client_key, request):
        self._read('get_default_realms', client_key=client_key, realms=[])
        return []

    def validate_requested_realms(self, client_key, realms, request):
        requested = list(realms or [])
        allowed = (
            client_key in self.clients
            and all(scope in self.realms for scope in requested)
        )
        self._read('validate_requested_realms', realms=requested,
                   allowed=allowed)
        return allowed

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
                                     request, request_token=None,
                                     access_token=None):
        token = request_token or access_token
        nonce_key = (
            client_key, timestamp, nonce, request_token, access_token
        )
        fresh = nonce_key not in self.used_nonces
        self._read('validate_timestamp_and_nonce', token, fresh=fresh)
        if fresh:
            self.used_nonces.add(nonce_key)
            self._write('remember_nonce', token)
        return fresh

    def save_request_token(self, token, request):
        request_token = token['oauth_token']
        requested_realms = list(getattr(request, 'realms', None) or [])
        self.request_tokens[request_token] = {
            'client_key': request.client_key,
            'secret': token['oauth_token_secret'],
            'callback_uri': request.redirect_uri,
            'requested_realms': requested_realms,
            'granted_realms': None,
            'verifier': None,
            'status': 'awaiting_confirmation',
            'invalidated': False,
        }
        self._write(
            'save_request_token',
            request_token,
            realms=requested_realms,
            status='awaiting_confirmation',
        )

    def verify_request_token(self, token, request):
        record = self.request_tokens.get(token)
        allowed = bool(record and not record['invalidated'])
        self._read(
            'verify_request_token',
            token,
            allowed=allowed,
            status=record['status'] if record else 'missing',
        )
        return allowed

    def verify_realms(self, token, realms, request):
        record = self.request_tokens.get(token)
        requested = record['requested_realms'] if record else []
        verified = list(realms or [])
        allowed = bool(record and set(verified).issubset(requested))
        self._read('verify_realms', token, realms=verified, allowed=allowed)
        return allowed

    def save_verifier(self, token, verifier, request):
        record = self.request_tokens[token]
        granted_realms = list(request.realms or [])
        record['verifier'] = verifier['oauth_verifier']
        record['granted_realms'] = granted_realms
        record['status'] = 'confirmed'
        self._write(
            'save_verifier',
            token,
            realms=granted_realms,
            status='confirmed',
        )

    def get_redirect_uri(self, token, request):
        record = self.request_tokens[token]
        self._read('get_redirect_uri', token,
                   redirect_uri=record['callback_uri'])
        return record['callback_uri']

    def validate_request_token(self, client_key, token, request):
        record = self.request_tokens.get(token)
        allowed = bool(
            record
            and record['client_key'] == client_key
            and not record['invalidated']
        )
        self._read(
            'validate_request_token',
            token,
            allowed=allowed,
            status=record['status'] if record else 'missing',
        )
        return allowed

    def validate_verifier(self, client_key, token, verifier, request):
        record = self.request_tokens.get(token)
        expected = record['verifier'] if record else None
        allowed = bool(expected) and safe_string_equals(verifier, expected)
        self._read('validate_verifier', token, allowed=allowed)
        return allowed

    def get_request_token_secret(self, client_key, token, request):
        record = self.request_tokens.get(token)
        valid = bool(record and record['client_key'] == client_key)
        self._read('get_request_token_secret', token, dummy=not valid)
        return record['secret'] if valid else DUMMY_REQUEST_SECRET

    def get_realms(self, token, request):
        record = self.request_tokens.get(token)
        if not record:
            realms = []
        elif record['granted_realms'] is not None:
            realms = list(record['granted_realms'])
        else:
            realms = list(record['requested_realms'])
        self._read('get_realms', token, realms=realms)
        return realms

    def save_access_token(self, token, request):
        access_token = token['oauth_token']
        granted_realms = list(request.realms or [])
        self.access_tokens[access_token] = {
            'client_key': request.client_key,
            'request_token': request.resource_owner_key,
            'secret': token['oauth_token_secret'],
            'realms': granted_realms,
            'status': 'active',
        }
        self._write(
            'save_access_token',
            access_token,
            request_token=request.resource_owner_key,
            realms=granted_realms,
            status='active',
        )

    def invalidate_request_token(self, client_key, request_token, request):
        record = self.request_tokens[request_token]
        record['invalidated'] = True
        record['status'] = 'exchanged'
        self._write('invalidate_request_token', request_token,
                    status='exchanged')

    def validate_access_token(self, client_key, token, request):
        record = self.access_tokens.get(token)
        allowed = bool(
            record
            and record['client_key'] == client_key
            and record['status'] == 'active'
        )
        self._read(
            'validate_access_token',
            token,
            allowed=allowed,
            status=record['status'] if record else 'missing',
        )
        return allowed

    def get_access_token_secret(self, client_key, token, request):
        record = self.access_tokens.get(token)
        valid = bool(record and record['client_key'] == client_key)
        self._read('get_access_token_secret', token, dummy=not valid)
        return record['secret'] if valid else DUMMY_ACCESS_SECRET

    def validate_realms(self, client_key, token, request, uri=None,
                        realms=None):
        record = self.access_tokens.get(token)
        required = list(realms or [])
        granted = list(record['realms']) if record else []
        allowed = bool(
            record
            and record['client_key'] == client_key
            and record['status'] == 'active'
            and set(required).issubset(granted)
        )
        self._read(
            'validate_realms',
            token,
            required=required,
            granted=granted,
            uri=uri,
            allowed=allowed,
        )
        return allowed


class SignatureOnlyTestDouble:
    """Test double whose assertion stops at the RFC 5849 signature."""

    def __init__(self, validator):
        self.endpoint = SignatureOnlyEndpoint(validator)
        self.signature_results = []

    def signature_passes(self, uri, headers):
        _valid, request = self.endpoint.validate_request(
            uri, headers=headers
        )
        passed = bool(
            request is not None
            and request.validator_log.get('signature') is True
        )
        self.signature_results.append(passed)
        return passed


class OAuth1ScopeAttributionRegressionTest(TestCase):

    def setUp(self):
        self.validator = RecordingGrantValidator()
        self.request_token_endpoint = RequestTokenEndpoint(self.validator)
        self.authorization_endpoint = AuthorizationEndpoint(self.validator)
        self.access_token_endpoint = AccessTokenEndpoint(self.validator)
        self.resource_endpoint = ResourceEndpoint(self.validator)

    def _client(self, *, realm=None, request_token=None,
                request_secret=None, verifier=None, access_token=None,
                access_secret=None):
        is_temporary_request = request_token is None and access_token is None
        return Client(
            CLIENT_KEY,
            client_secret=CLIENT_SECRET,
            resource_owner_key=access_token or request_token,
            resource_owner_secret=access_secret or request_secret,
            callback_uri=CALLBACK_URI if is_temporary_request else None,
            verifier=verifier,
            realm=realm,
            signature_method=SIGNATURE_HMAC_SHA256,
        )

    def request_temporary_credentials(self, scope):
        client = self._client(realm=scope)
        uri, headers, _body = client.sign(REQUEST_TOKEN_URL)
        response_headers, body, status = (
            self.request_token_endpoint.create_request_token_response(
                uri, headers=headers
            )
        )
        credentials = dict(parse_qsl(body or ''))
        journey = SimpleNamespace(
            scope=scope,
            request_token=credentials.get('oauth_token'),
            request_secret=credentials.get('oauth_token_secret'),
            verifier=None,
            access_token=None,
            access_secret=None,
        )
        response = SimpleNamespace(
            headers=response_headers,
            body=body,
            status_code=status,
            credentials=credentials,
        )
        return journey, response

    def approve(self, journey):
        authorization_uri = (
            f'{AUTHORIZE_URL}?oauth_token={journey.request_token}'
        )
        headers, body, status = (
            self.authorization_endpoint.create_authorization_response(
                authorization_uri,
                realms=[journey.scope],
            )
        )
        if status == 302:
            query = parse_qs(urlparse(headers['Location']).query)
            journey.verifier = query['oauth_verifier'][0]
        return SimpleNamespace(headers=headers, body=body, status_code=status)

    def exchange_credentials(self, journey, verifier=None):
        presented_verifier = (
            journey.verifier if verifier is None else verifier
        )
        client = self._client(
            request_token=journey.request_token,
            request_secret=journey.request_secret,
            verifier=presented_verifier,
        )
        uri, headers, _body = client.sign(ACCESS_TOKEN_URL)
        response_headers, body, status = (
            self.access_token_endpoint.create_access_token_response(
                uri, headers=headers
            )
        )
        credentials = dict(parse_qsl(body or ''))
        if status == 200:
            journey.access_token = credentials['oauth_token']
            journey.access_secret = credentials['oauth_token_secret']
        return SimpleNamespace(
            headers=response_headers,
            body=body,
            status_code=status,
            credentials=credentials,
        )

    def sign_resource_request(self, token, secret, resource_url):
        client = self._client(access_token=token, access_secret=secret)
        return client.sign(resource_url)

    def request_resource(self, token, secret, resource_url, required_scope):
        uri, headers, _body = self.sign_resource_request(
            token, secret, resource_url
        )
        valid, oauth_request = (
            self.resource_endpoint.validate_protected_resource_request(
                uri,
                headers=headers,
                realms=[required_scope],
            )
        )
        status_code = 200 if valid else 403
        body = (
            f'{{"ok":true,"scope":"{required_scope}"}}'
            if valid else '{"ok":false}'
        )
        validator_log = (
            dict(oauth_request.validator_log)
            if oauth_request is not None else {}
        )
        return SimpleNamespace(
            status_code=status_code,
            body=body,
            valid=valid,
            validator_log=validator_log,
        )

    def complete_journey(self, scope):
        journey, temporary_response = self.request_temporary_credentials(scope)
        self.assertEqual(200, temporary_response.status_code)
        approval = self.approve(journey)
        self.assertEqual(302, approval.status_code)
        exchange = self.exchange_credentials(journey)
        self.assertEqual(200, exchange.status_code)
        return journey

    def assert_completed_journey_facts(self, journey):
        access_record = self.validator.access_tokens[journey.access_token]
        self.assertEqual(CLIENT_KEY, access_record['client_key'])
        self.assertEqual(journey.request_token,
                         access_record['request_token'])
        self.assertEqual([journey.scope], access_record['realms'])
        self.assertEqual('active', access_record['status'])

        request_record = self.validator.request_tokens[journey.request_token]
        self.assertEqual([journey.scope],
                         request_record['requested_realms'])
        self.assertEqual([journey.scope], request_record['granted_realms'])
        self.assertEqual('exchanged', request_record['status'])
        self.assertTrue(request_record['invalidated'])

        request_reads = self.validator.operations_for(
            'reads', journey.request_token
        )
        for operation in (
            'verify_request_token',
            'verify_realms',
            'get_redirect_uri',
            'validate_request_token',
            'validate_verifier',
            'get_request_token_secret',
            'get_realms',
        ):
            self.assertIn(operation, request_reads)

        request_writes = [
            fact
            for fact in self.validator.writes
            if fact.get('token') == journey.request_token
        ]
        request_write_ops = [
            fact['op'] for fact in request_writes
            if fact['op'] != 'remember_nonce'
        ]
        self.assertEqual(
            [
                'save_request_token',
                'save_verifier',
                'invalidate_request_token',
            ],
            request_write_ops,
        )
        verifier_write = next(
            fact for fact in request_writes
            if fact['op'] == 'save_verifier'
        )
        self.assertEqual([journey.scope], verifier_write['realms'])

        access_reads = self.validator.operations_for(
            'reads', journey.access_token
        )
        for operation in (
            'validate_access_token',
            'get_access_token_secret',
            'validate_realms',
        ):
            self.assertIn(operation, access_reads)

        access_write_facts = [
            fact
            for fact in self.validator.writes
            if fact.get('token') == journey.access_token
            and fact['op'] != 'remember_nonce'
        ]
        self.assertEqual(
            ['save_access_token'],
            [fact['op'] for fact in access_write_facts],
        )
        self.assertEqual(
            [journey.scope], access_write_facts[0]['realms']
        )

    def assert_temporary_credentials_pending(self, journey, response):
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            'true', response.credentials['oauth_callback_confirmed']
        )
        record = self.validator.request_tokens[journey.request_token]
        self.assertEqual([journey.scope], record['requested_realms'])
        self.assertIsNone(record['granted_realms'])
        self.assertEqual('awaiting_confirmation', record['status'])
        self.assertEqual({}, self.validator.active_access_grants(CLIENT_KEY))

    def approve_successfully(self, journey):
        approval = self.approve(journey)
        self.assertEqual(302, approval.status_code)
        self.assertIsNotNone(journey.verifier)
        return approval

    def assert_scope_granted(self, journey):
        record = self.validator.request_tokens[journey.request_token]
        self.assertEqual([journey.scope], record['granted_realms'])
        self.assertEqual('confirmed', record['status'])

    def assert_awaiting_confirmation(self, journey):
        record = self.validator.request_tokens[journey.request_token]
        self.assertIsNone(record['granted_realms'])
        self.assertEqual('awaiting_confirmation', record['status'])

    def assert_premature_exchange_rejected(self, journey):
        response = self.exchange_credentials(
            journey, verifier=UNAPPROVED_VERIFIER
        )
        self.assertEqual(401, response.status_code)
        self.assertIsNone(response.body)
        self.assertNotIn('oauth_token', response.credentials)
        self.assertNotIn(
            journey.request_token, self.validator.access_tokens
        )
        verifier_reads = [
            fact
            for fact in self.validator.reads
            if fact['op'] == 'validate_verifier'
            and fact['token'] == journey.request_token
        ]
        self.assertFalse(verifier_reads[-1]['allowed'])

    def exchange_successfully(self, journey):
        response = self.exchange_credentials(journey)
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            journey.scope,
            response.credentials['oauth_authorized_realms'],
        )
        self.assertEqual(
            [journey.scope],
            self.validator.access_tokens[journey.access_token]['realms'],
        )
        return response

    def assert_only_active_grant(self, access_token, pending_request_token):
        active_grants = self.validator.active_access_grants(CLIENT_KEY)
        self.assertEqual([access_token], list(active_grants))
        self.assertNotIn(pending_request_token, active_grants)

    def assert_temporary_token_unusable(self, journey, resource_url):
        self.assertFalse(
            self.validator.validate_access_token(
                CLIENT_KEY, journey.request_token, None
            )
        )
        response = self.request_resource(
            journey.request_token,
            journey.request_secret,
            resource_url,
            journey.scope,
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual('{"ok":false}', response.body)
        self.assertFalse(response.valid)
        self.assertFalse(response.validator_log['resource_owner'])

    def assert_resource_allowed(self, journey, resource_url):
        response = self.request_resource(
            journey.access_token,
            journey.access_secret,
            resource_url,
            journey.scope,
        )
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.valid)
        self.assertEqual(
            f'{{"ok":true,"scope":"{journey.scope}"}}', response.body
        )
        self.assertEqual(
            {
                'client': True,
                'resource_owner': True,
                'realm': True,
                'signature': True,
            },
            response.validator_log,
        )
        return response

    def assert_cross_scope_denied(self, journey, resource_url,
                                  required_scope):
        response = self.request_resource(
            journey.access_token,
            journey.access_secret,
            resource_url,
            required_scope,
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual('{"ok":false}', response.body)
        self.assertFalse(response.valid)
        self.assertTrue(response.validator_log['signature'])
        self.assertFalse(response.validator_log['realm'])
        return response

    def test_concurrent_journeys_keep_approved_scopes_bound_to_own_tokens(self):
        """Interleave two in-flight tokens for one consumer key.

        The deterministic ordering keeps reports pending while billing is
        approved, exchanged, and used before reports is confirmed and retried.
        """
        reports, reports_temporary = self.request_temporary_credentials(
            REPORTS_SCOPE
        )
        billing, billing_temporary = self.request_temporary_credentials(
            BILLING_SCOPE
        )
        self.assert_temporary_credentials_pending(
            reports, reports_temporary
        )
        self.assert_temporary_credentials_pending(
            billing, billing_temporary
        )

        self.approve_successfully(billing)
        self.assert_scope_granted(billing)
        self.assert_awaiting_confirmation(reports)

        self.assert_premature_exchange_rejected(reports)
        self.exchange_successfully(billing)
        self.assert_only_active_grant(
            billing.access_token, reports.request_token
        )
        self.assert_temporary_token_unusable(
            reports, REPORTS_RESOURCE_URL
        )

        self.assert_resource_allowed(billing, BILLING_RESOURCE_URL)
        self.assert_cross_scope_denied(
            billing, REPORTS_RESOURCE_URL, REPORTS_SCOPE
        )

        self.approve_successfully(reports)
        reports_retry = self.exchange_successfully(reports)
        self.assertEqual(
            REPORTS_SCOPE,
            reports_retry.credentials['oauth_authorized_realms'],
        )

        active_grants = self.validator.active_access_grants(CLIENT_KEY)
        self.assertCountEqual(
            [reports.access_token, billing.access_token],
            list(active_grants),
        )

        self.assert_resource_allowed(reports, REPORTS_RESOURCE_URL)
        self.assert_cross_scope_denied(
            reports, BILLING_RESOURCE_URL, BILLING_SCOPE
        )
        self.assert_resource_allowed(billing, BILLING_RESOURCE_URL)

        self.assert_completed_journey_facts(reports)
        self.assert_completed_journey_facts(billing)

    def test_signature_only_double_misses_scope_attribution_fault(self):
        journey = self.complete_journey(REPORTS_SCOPE)

        healthy_response = self.request_resource(
            journey.access_token,
            journey.access_secret,
            REPORTS_RESOURCE_URL,
            REPORTS_SCOPE,
        )
        self.assertEqual(200, healthy_response.status_code)

        # Fault injection: the token and signing secret remain intact, but the
        # application storage attributes the grant to the wrong scope.
        self.validator.access_tokens[journey.access_token]['realms'] = [
            BILLING_SCOPE
        ]

        double_uri, double_headers, _body = self.sign_resource_request(
            journey.access_token,
            journey.access_secret,
            REPORTS_RESOURCE_URL,
        )
        resource_uri, resource_headers, _body = self.sign_resource_request(
            journey.access_token,
            journey.access_secret,
            REPORTS_RESOURCE_URL,
        )

        signature_double = SignatureOnlyTestDouble(self.validator)
        self.assertTrue(
            signature_double.signature_passes(double_uri, double_headers)
        )

        valid, oauth_request = (
            self.resource_endpoint.validate_protected_resource_request(
                resource_uri,
                headers=resource_headers,
                realms=[REPORTS_SCOPE],
            )
        )

        self.assertFalse(valid)
        self.assertTrue(oauth_request.validator_log['signature'])
        self.assertFalse(oauth_request.validator_log['realm'])
        self.assertEqual([True], signature_double.signature_results)
