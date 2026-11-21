import base64
import unittest
from collections import Counter

from flask import Flask
from flask_httpauth import AuthResult, AuthStatus, HTTPBasicAuth


class FakeDirectory:
    """In-memory employee directory used by the tests.

    ``employees`` maps usernames to ``(password, active)`` tuples.
    ``available`` simulates an identity directory outage.
    """

    def __init__(self):
        self.employees = {
            'john': ('hello', True),
            'susan': ('bye', True),
            'cindy': ('byebye', False),
        }
        self.available = True
        self.lookups = 0
        self.audit = Counter()

    def verify(self, username, password):
        self.lookups += 1
        if not self.available:
            return AuthResult.unavailable()
        employee = self.employees.get(username)
        if employee is None or employee[0] != password:
            return AuthResult.rejected()
        if not employee[1]:
            return AuthResult.disabled()
        return AuthResult.ok({'username': username, 'roles': ['normal']})

    def record(self, result):
        self.audit[result.status] += 1


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.business_calls = 0

        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        auth = HTTPBasicAuth()

        @auth.verify_password
        def verify_password(username, password):
            return self.directory.verify(username, password)

        @auth.auth_audit
        def auth_audit(result):
            self.directory.record(result)

        @app.route('/private')
        @auth.login_required
        def private():
            self.business_calls += 1
            return 'private:' + auth.current_user()['username']

        self.app = app
        self.auth = auth
        self.client = app.test_client()

    def get(self, username, password):
        creds = base64.b64encode(
            f'{username}:{password}'.encode()).decode()
        return self.client.get(
            '/private', headers={'Authorization': 'Basic ' + creds})

    def test_valid_credentials_reach_the_view(self):
        response = self.get('john', 'hello')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'private:john')
        self.assertEqual(self.business_calls, 1)
        self.assertEqual(self.directory.audit[AuthStatus.OK], 1)

    def test_wrong_password_is_rejected(self):
        response = self.get('john', 'wrong')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.business_calls, 0)
        self.assertEqual(self.directory.audit[AuthStatus.REJECTED], 1)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_unknown_account_is_rejected(self):
        response = self.get('nobody', 'whatever')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.business_calls, 0)
        self.assertEqual(self.directory.audit[AuthStatus.REJECTED], 1)

    def test_disabled_account_is_rejected_like_wrong_credentials(self):
        disabled = self.get('cindy', 'byebye')
        wrong_password = self.get('john', 'wrong')
        unknown = self.get('nobody', 'whatever')
        self.assertEqual(disabled.status_code, 401)
        self.assertEqual(self.business_calls, 0)
        self.assertEqual(self.directory.audit[AuthStatus.DISABLED], 1)
        # The response must not reveal that the account exists.
        for other in (wrong_password, unknown):
            self.assertEqual(disabled.status_code, other.status_code)
            self.assertEqual(disabled.data, other.data)
            self.assertEqual(disabled.headers['WWW-Authenticate'],
                             other.headers['WWW-Authenticate'])

    def test_directory_outage_is_not_an_auth_rejection(self):
        self.directory.available = False
        response = self.get('john', 'hello')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.business_calls, 0)
        self.assertEqual(self.directory.audit[AuthStatus.UNAVAILABLE], 1)
        self.assertEqual(self.directory.audit[AuthStatus.REJECTED], 0)
        # A server-side outage must not ask the client to retry credentials.
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_directory_recovers(self):
        self.directory.available = False
        self.assertEqual(self.get('john', 'hello').status_code, 503)
        self.directory.available = True
        self.assertEqual(self.get('john', 'hello').status_code, 200)
        self.assertEqual(self.business_calls, 1)

    def test_each_attempt_is_audited_once(self):
        self.get('john', 'hello')
        self.get('john', 'wrong')
        self.get('cindy', 'byebye')
        self.directory.available = False
        self.get('susan', 'bye')
        self.assertEqual(self.directory.audit, {
            AuthStatus.OK: 1,
            AuthStatus.REJECTED: 1,
            AuthStatus.DISABLED: 1,
            AuthStatus.UNAVAILABLE: 1,
        })
        self.assertEqual(self.business_calls, 1)
        self.assertEqual(self.directory.lookups, 4)


class CustomErrorHandlerTestCase(unittest.TestCase):
    """The application can branch on the status in its error handler."""

    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'
        auth = HTTPBasicAuth()
        self.available = True

        @auth.verify_password
        def verify_password(username, password):
            if not self.available:
                return AuthResult.unavailable()
            return AuthResult.rejected()

        @auth.error_handler
        def auth_error(status):
            if status == 503:
                response = app.make_response(('directory down', status))
                response.headers['Retry-After'] = '30'
                return response
            return 'invalid credentials', status

        @app.route('/')
        @auth.login_required
        def index():
            return 'index'

        self.app = app
        self.client = app.test_client()

    def test_unavailable_branch(self):
        self.available = False
        creds = base64.b64encode(b'john:hello').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, b'directory down')
        self.assertEqual(response.headers['Retry-After'], '30')
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_rejected_branch(self):
        creds = base64.b64encode(b'john:hello').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'invalid credentials')
        self.assertTrue('WWW-Authenticate' in response.headers)


class LegacyReturnValuesTestCase(unittest.TestCase):
    """Existing callbacks that return user objects keep working."""

    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'
        auth = HTTPBasicAuth()

        @auth.verify_password
        def verify_password(username, password):
            if username == 'john' and password == 'hello':
                return {'name': 'john'}
            if username == 'true' and password == 'true':
                return True
            return False

        @app.route('/')
        @auth.login_required
        def index():
            return 'index'

        self.app = app
        self.client = app.test_client()

    def test_user_object(self):
        creds = base64.b64encode(b'john:hello').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)

    def test_boolean_true(self):
        creds = base64.b64encode(b'true:true').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)

    def test_boolean_false(self):
        creds = base64.b64encode(b'john:wrong').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)


class OkWithoutUserTestCase(unittest.TestCase):
    """AuthResult.ok() with no user behaves like returning True."""

    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'
        self.auth = HTTPBasicAuth()

        @self.auth.verify_password
        def verify_password(username, password):
            return AuthResult.ok()

        @app.route('/')
        @self.auth.login_required
        def index():
            return 'user:{}:{}'.format(
                self.auth.current_user(),
                self.auth.auth_result().status.value)

        self.app = app
        self.client = app.test_client()

    def test_username_is_current_user(self):
        creds = base64.b64encode(b'susan:bye').decode()
        response = self.client.get(
            '/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'user:susan:ok')


class AuthResultTestCase(unittest.TestCase):
    def test_defaults(self):
        result = AuthResult.ok()
        self.assertEqual(result.status, AuthStatus.OK)
        self.assertIsNone(result.user)
        self.assertIsNone(result.username)

    def test_string_status_is_normalized(self):
        result = AuthResult('disabled')
        self.assertEqual(result.status, AuthStatus.DISABLED)

    def test_invalid_status_is_rejected(self):
        with self.assertRaises(ValueError):
            AuthResult('nope')

    def test_status_is_string_accessible(self):
        self.assertEqual(AuthStatus.DISABLED.value, 'disabled')
        self.assertEqual(AuthStatus.DISABLED, 'disabled')


if __name__ == '__main__':
    unittest.main()
