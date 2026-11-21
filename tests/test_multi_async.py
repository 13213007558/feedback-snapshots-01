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
        token_auth = HTTPTokenAuth('MyToken')
        custom_token_auth = HTTPTokenAuth(header='X-Token')
        multi_auth = MultiAuth(basic_auth, token_auth, custom_token_auth)
        self.verify_calls = {'basic': 0, 'token': 0, 'custom_token': 0}

        @basic_auth.verify_password
        async def verify_password(username, password):
            self.verify_calls['basic'] += 1
            if username == 'john' and password == 'hello':
                return 'john'

        @basic_auth.get_user_roles
        async def get_basic_role(username):
            if username == 'john':
                return ['foo', 'bar']

        @token_auth.verify_token
        async def verify_token(token):
            self.verify_calls['token'] += 1
            return token == 'this-is-the-token!'

        @token_auth.get_user_roles
        async def get_token_role(auth):
            if auth.token == 'this-is-the-token!':
                return 'foo'
            return

        @token_auth.error_handler
        async def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @custom_token_auth.verify_token
        async def verify_custom_token(token):
            self.verify_calls['custom_token'] += 1
            return token == 'this-is-the-custom-token!'

        @custom_token_auth.get_user_roles
        async def get_custom_token_role(auth):
            if auth.token == 'this-is-the-custom-token!':
                return 'foo'
            return

        @app.route('/')
        async def index():
            return 'index'

        @app.route('/protected')
        @multi_auth.login_required
        async def auth_route():
            return 'access granted:' + str(multi_auth.current_user())

        @app.route('/protected-with-role')
        @multi_auth.login_required(role='foo')
        async def auth_role_route():
            return 'role access granted'

        @app.route('/basic-only')
        @multi_auth.login_required(allowed_schemes='Basic')
        async def basic_only_route():
            return 'basic only:' + multi_auth.current_scheme()

        @app.route('/token-only')
        @multi_auth.login_required(allowed_schemes=['MyToken'])
        async def token_only_route():
            return 'token only:' + multi_auth.current_scheme()

        @app.route('/basic-or-token')
        @multi_auth.login_required(allowed_schemes=['Basic', 'MyToken'])
        async def basic_or_token_route():
            return 'auth:' + multi_auth.current_scheme()

        @app.route('/token-only-optional')
        @multi_auth.login_required(allowed_schemes=['MyToken'],
                                   optional=True)
        async def token_only_optional_route():
            return 'optional:' + str(multi_auth.current_scheme()) + ':' + \
                str(multi_auth.current_user())

        self.app = app
        self.multi_auth = multi_auth
        self.client = app.test_client()

    def test_multi_auth_prompt(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_login_valid_basic(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/protected', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:john')

    def test_multi_auth_login_invalid_basic(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/protected', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_login_valid_token(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:None')

    def test_multi_auth_login_invalid_token(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_multi_auth_login_valid_custom_token(self):
        response = self.client.get(
            '/protected', headers={'X-Token': 'this-is-the-custom-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:None')

    def test_multi_auth_login_invalid_custom_token(self):
        response = self.client.get(
            '/protected', headers={'X-Token': 'this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    def test_multi_auth_login_invalid_scheme(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'Foo this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_malformed_header(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'token-without-scheme'})
        self.assertEqual(response.status_code, 401)

    def test_multi_auth_login_valid_basic_role(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/protected-with-role', headers={'Authorization':
                                             'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')

    def test_multi_auth_login_valid_token_role(self):
        response = self.client.get(
            '/protected-with-role', headers={'Authorization':
                                             'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')

    def test_multi_auth_login_valid_custom_token_role(self):
        response = self.client.get(
            '/protected-with-role', headers={'X-Token':
                                             'this-is-the-custom-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')

    def test_allowed_scheme_valid_basic(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-only', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'basic only:Basic')
        self.assertEqual(self.verify_calls,
                         {'basic': 1, 'token': 0, 'custom_token': 0})

    def test_allowed_scheme_valid_token(self):
        response = self.client.get(
            '/token-only', headers={'Authorization':
                                    'MyToken this-is-the-token!'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'token only:MyToken')
        self.assertEqual(self.verify_calls,
                         {'basic': 0, 'token': 1, 'custom_token': 0})

    def test_allowed_schemes_reports_actual_scheme(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-or-token', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'auth:Basic')

        response = self.client.get(
            '/basic-or-token', headers={'Authorization':
                                        'MyToken this-is-the-token!'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'auth:MyToken')

    def test_allowed_scheme_rejects_other_configured_scheme(self):
        response = self.client.get(
            '/basic-only', headers={'Authorization':
                                    'MyToken this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')
        self.assertEqual(self.verify_calls,
                         {'basic': 0, 'token': 0, 'custom_token': 0})

    def test_allowed_schemes_rejects_other_custom_header(self):
        response = self.client.get(
            '/basic-or-token',
            headers={'X-Token': 'this-is-the-custom-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')
        self.assertEqual(self.verify_calls,
                         {'basic': 0, 'token': 0, 'custom_token': 0})

    def test_allowed_scheme_without_credentials(self):
        response = self.client.get('/basic-only')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')
        self.assertEqual(self.verify_calls,
                         {'basic': 1, 'token': 0, 'custom_token': 0})

    def test_allowed_scheme_without_credentials_uses_selected_error_handler(
            self):
        response = self.client.get('/token-only')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'error')
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_allowed_scheme_invalid_credentials(self):
        response = self.client.get(
            '/basic-only', headers={'Authorization':
                                    'Basic ' + base64.b64encode(
                                        b'john:bye').decode('utf-8')})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.verify_calls,
                         {'basic': 1, 'token': 0, 'custom_token': 0})

    def test_allowed_scheme_optional_anonymous(self):
        response = self.client.get('/token-only-optional')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'),
                         'optional:MyToken:None')
        self.assertEqual(self.verify_calls,
                         {'basic': 0, 'token': 0, 'custom_token': 0})

    def test_allowed_scheme_optional_rejects_other_scheme(self):
        response = self.client.get(
            '/token-only-optional',
            headers={'Authorization': 'Basic ' + base64.b64encode(
                b'john:hello').decode('utf-8')})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.verify_calls,
                         {'basic': 0, 'token': 0, 'custom_token': 0})

    def test_undeclared_route_keeps_accepting_all_schemes(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.verify_calls,
                         {'basic': 1, 'token': 0, 'custom_token': 0})

        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/protected', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)

        response = self.client.get(
            '/protected', headers={'X-Token':
                                   'this-is-the-custom-token!'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'access granted:None')

    def test_unknown_allowed_scheme(self):
        with self.assertRaises(ValueError):
            self.multi_auth.login_required(allowed_schemes=['Nonexistent'])

    def test_empty_allowed_schemes(self):
        with self.assertRaises(ValueError):
            self.multi_auth.login_required(allowed_schemes=[])

    def test_anonymous_readable_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'index')
