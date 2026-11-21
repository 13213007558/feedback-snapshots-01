import base64
import sys
import unittest
from flask import Flask
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
import pytest


@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        token_auth = HTTPTokenAuth('Bearer')
        custom_token_auth = HTTPTokenAuth(header='X-API-Key')
        multi_auth = MultiAuth(basic_auth, token_auth, custom_token_auth)

        @basic_auth.verify_password
        async def verify_password(username, password):
            if username == 'john' and password == 'hello':
                return 'john'

        @token_auth.verify_token
        async def verify_token(token):
            if token == 'valid-token':
                return 'token-user'

        @custom_token_auth.verify_token
        async def verify_custom_token(token):
            if token == 'valid-custom-token':
                return 'custom-user'

        @app.route('/public')
        @multi_auth.login_required(optional=True)
        async def public_route():
            user = multi_auth.current_user()
            if user is None:
                return 'public summary:anonymous'
            return 'public summary:authenticated:' + str(user)

        @app.route('/private')
        @multi_auth.login_required
        async def private_route():
            return 'private:' + str(multi_auth.current_user())

        self.app = app
        self.multi_auth = multi_auth
        self.client = app.test_client()

    def assert_anonymous_summary(self, headers=None):
        response = self.client.get('/public', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.data.decode('utf-8'),
                         'public summary:anonymous')

    def assert_authenticated_summary(self, headers, user):
        response = self.client.get('/public', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.data.decode('utf-8'),
                         'public summary:authenticated:' + user)

    def test_optional_no_credentials_is_anonymous(self):
        self.assert_anonymous_summary()

    def test_optional_authorization_header_valid_is_authenticated(self):
        self.assert_authenticated_summary(
            {'Authorization': 'Bearer valid-token'}, 'token-user')

    def test_optional_authorization_header_failed_is_anonymous(self):
        self.assert_anonymous_summary(
            {'Authorization': 'Bearer not-a-valid-token'})

    def test_optional_custom_header_valid_is_authenticated(self):
        self.assert_authenticated_summary(
            {'X-API-Key': 'valid-custom-token'}, 'custom-user')

    def test_optional_custom_header_failed_verification_is_anonymous(self):
        self.assert_anonymous_summary(
            {'X-API-Key': 'not-a-valid-custom-token'})

    def test_optional_basic_credentials_valid_is_authenticated(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        self.assert_authenticated_summary(
            {'Authorization': 'Basic ' + creds}, 'john')

    def test_optional_basic_credentials_failed_verification_is_anonymous(self):
        creds = base64.b64encode(b'john:wrong-password').decode('utf-8')
        self.assert_anonymous_summary(
            {'Authorization': 'Basic ' + creds})

    def test_failed_verification_without_optional_is_rejected(self):
        response = self.client.get(
            '/private', headers={'Authorization': 'Bearer not-a-valid-token'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)

    def test_no_credentials_without_optional_is_rejected(self):
        response = self.client.get('/private')
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
