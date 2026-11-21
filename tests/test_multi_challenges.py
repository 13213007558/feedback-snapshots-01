import base64
import unittest

from flask import Flask, jsonify, abort
from werkzeug.http import parse_dict_header

from flask_httpauth import (
    HTTPBasicAuth, HTTPDigestAuth, HTTPTokenAuth, MultiAuth)


def _basic_credentials(username, password):
    return base64.b64encode(
        f'{username}:{password}'.encode('utf-8')).decode('utf-8')


class MultiAuthChallengeTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        # Two independently configured realms that advertise distinct schemes.
        basic_auth = HTTPBasicAuth(realm='Web Console')
        token_auth = HTTPTokenAuth('Bearer', realm='API Tokens')
        digest_auth = HTTPDigestAuth(realm='Digest Realm')
        multi_auth = MultiAuth(basic_auth, token_auth)
        digest_multi_auth = MultiAuth(digest_auth, basic_auth)

        @basic_auth.verify_password
        def verify_password(username, password):
            if username == 'john' and password == 'hello':
                return 'john'

        @basic_auth.get_user_roles
        def get_basic_roles(user):
            return ['admin'] if user == 'john' else []

        @token_auth.verify_token
        def verify_token(token):
            return 'token-user' if token == 'secret-token' else None

        @token_auth.get_user_roles
        def get_token_roles(user):
            return ['admin']

        @digest_auth.get_password
        def get_digest_password(username):
            if username == 'john':
                return 'hello'

        def auth_error(status):
            # Unified JSON layer used by every configured authentication
            # object. The framework still owns the WWW-Authenticate challenges.
            if status == 403:
                payload = {'error': 'forbidden',
                           'message': 'authenticated but not permitted'}
                return jsonify(payload), 403
            payload = {'error': 'authentication_required',
                       'message': 'valid credentials are required'}
            return jsonify(payload), 401

        basic_auth.error_handler(auth_error)
        token_auth.error_handler(auth_error)
        digest_auth.error_handler(auth_error)

        @app.errorhandler(418)
        def teapot_error(error):
            return jsonify({'error': 'teapot'}), 418

        @app.route('/protected')
        @multi_auth.login_required
        def protected():
            return jsonify(user=multi_auth.current_user())

        @app.route('/admin')
        @multi_auth.login_required(role='admin')
        def admin():
            return jsonify(user=multi_auth.current_user())

        @app.route('/superadmin')
        @multi_auth.login_required(role='superadmin')
        def superadmin():
            return jsonify(user=multi_auth.current_user())

        @app.route('/digest-protected')
        @digest_multi_auth.login_required
        def digest_protected():
            return 'ok'

        @app.route('/boom')
        def boom():
            abort(418)

        self.app = app
        self.client = app.test_client()
        self.basic_auth = basic_auth
        self.token_auth = token_auth
        self.digest_auth = digest_auth
        self.expected_challenges = [
            'Basic realm="Web Console"',
            'Bearer realm="API Tokens"',
        ]

    def test_unauthenticated_401_emits_every_configured_challenge(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.getlist('WWW-Authenticate'),
            self.expected_challenges)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json(), {
            'error': 'authentication_required',
            'message': 'valid credentials are required',
        })

    def test_invalid_basic_credentials_401_keeps_static_challenges(self):
        response = self.client.get(
            '/protected',
            headers={'Authorization':
                     'Basic ' + _basic_credentials('john', 'wrong')})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.getlist('WWW-Authenticate'),
            self.expected_challenges)
        self.assertEqual(response.get_json()['error'],
                         'authentication_required')

    def test_invalid_token_401_keeps_static_challenges(self):
        response = self.client.get(
            '/protected',
            headers={'Authorization': 'Bearer not-a-real-token'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.getlist('WWW-Authenticate'),
            self.expected_challenges)

    def test_unknown_scheme_cannot_inject_challenge(self):
        # A crafted scheme must not appear in the response; only configured
        # challenges are published.
        response = self.client.get(
            '/protected',
            headers={'Authorization':
                     'Foo realm="Evil Realm", token="pwn"'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.getlist('WWW-Authenticate'),
            self.expected_challenges)

    def test_static_challenge_set_is_stable_across_requests(self):
        seen = []
        requests = [
            {},
            {'Authorization': 'Basic ' + _basic_credentials('x', 'y')},
            {'Authorization': 'Bearer some-token'},
            {'Authorization': 'UnsupportedScheme value'},
        ]
        for headers in requests:
            response = self.client.get('/protected', headers=headers)
            self.assertEqual(response.status_code, 401)
            seen.append(response.headers.getlist('WWW-Authenticate'))
        for challenges in seen:
            self.assertEqual(challenges, self.expected_challenges)

    def test_authenticated_missing_permission_is_403(self):
        response = self.client.get(
            '/superadmin',
            headers={'Authorization':
                     'Basic ' + _basic_credentials('john', 'hello')})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json(), {
            'error': 'forbidden',
            'message': 'authenticated but not permitted',
        })
        # Role failures still advertise every configured scheme so the client
        # knows which authentication options remain available.
        self.assertEqual(
            response.headers.getlist('WWW-Authenticate'),
            self.expected_challenges)

        # The same authenticated user with the required role is allowed in.
        allowed = self.client.get(
            '/admin',
            headers={'Authorization':
                     'Basic ' + _basic_credentials('john', 'hello')})
        self.assertEqual(allowed.status_code, 200)
        self.assertNotIn('WWW-Authenticate', allowed.headers)

    def test_application_error_is_not_rewritten_by_auth_layer(self):
        response = self.client.get('/boom')
        self.assertEqual(response.status_code, 418)
        self.assertNotIn('WWW-Authenticate', response.headers)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json(), {'error': 'teapot'})

    def test_valid_credentials_grant_access_without_challenges(self):
        response = self.client.get(
            '/protected',
            headers={'Authorization':
                     'Basic ' + _basic_credentials('john', 'hello')})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.get_json(), {'user': 'john'})

        response = self.client.get(
            '/protected', headers={'Authorization': 'Bearer secret-token'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('WWW-Authenticate', response.headers)

    def test_digest_challenge_is_published_alongside_other_realms(self):
        first = self.client.get('/digest-protected')
        self.assertEqual(first.status_code, 401)
        challenges = first.headers.getlist('WWW-Authenticate')
        self.assertEqual(len(challenges), 2)
        self.assertTrue(challenges[0].startswith(
            'Digest realm="Digest Realm",nonce='))
        self.assertEqual(challenges[1], 'Basic realm="Web Console"')
        digest_params = parse_dict_header(
            challenges[0][len('Digest '):])
        self.assertEqual(digest_params['realm'], 'Digest Realm')
        self.assertIn('nonce', digest_params)

        # A request carrying an unrelated scheme does not alter the published
        # realms or their ordering.
        second = self.client.get(
            '/digest-protected',
            headers={'Authorization': 'Bearer something'})
        second_challenges = second.headers.getlist('WWW-Authenticate')
        self.assertEqual(len(second_challenges), 2)
        self.assertTrue(second_challenges[0].startswith(
            'Digest realm="Digest Realm",nonce='))
        self.assertEqual(second_challenges[1], 'Basic realm="Web Console"')

    def test_explicit_challenge_subset(self):
        subset = MultiAuth(
            self.basic_auth, self.token_auth,
            challenges=[self.token_auth])
        self.assertEqual(subset.challenge_headers(),
                         ['Bearer realm="API Tokens"'])

        single = MultiAuth(
            self.basic_auth, self.token_auth,
            challenges=self.basic_auth)
        self.assertEqual(single.challenge_headers(),
                         ['Basic realm="Web Console"'])

        deduped = MultiAuth(
            self.basic_auth, self.token_auth,
            challenges=[self.token_auth, self.token_auth])
        self.assertEqual(len(deduped.challenge_headers()), 1)

    def test_challenge_must_reference_configured_auth(self):
        foreign = HTTPBasicAuth(realm='Not Part Of MultiAuth')
        with self.assertRaises(ValueError):
            MultiAuth(self.basic_auth, self.token_auth,
                      challenges=[foreign])
