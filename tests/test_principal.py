import unittest
import base64
from hashlib import md5 as basic_md5
from flask import Flask
from flask_httpauth import (
    AuthenticatedPrincipal, HTTPBasicAuth, HTTPDigestAuth, MultiAuth)
from werkzeug.datastructures import Authorization
from werkzeug.http import parse_dict_header


def md5(str):
    if type(str).__name__ == 'str':
        str = str.encode('utf-8')
    return basic_md5(str)


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        digest_auth = HTTPDigestAuth()
        multi_auth = MultiAuth(digest_auth, basic_auth)

        self.principals = []

        @basic_auth.verify_password
        def verify_password(username, password):
            if username == 'svc' and password == 'basic-pass':
                return True
            return False

        @digest_auth.get_password
        def get_digest_password(username):
            if username == 'svc':
                return 'digest-pass'

        def get_roles(principal):
            self.principals.append(principal)
            if principal.username != 'svc':
                return None
            if principal.scheme == 'Basic':
                # roles for intranet administrators
                return ['intranet', 'reports']
            elif principal.scheme == 'Digest':
                # roles for automation services
                return ['automation', 'reports']

        basic_auth.get_user_roles(get_roles)
        digest_auth.get_user_roles(get_roles)

        @app.route('/')
        def index():
            return 'index'

        @app.route('/intranet')
        @multi_auth.login_required(role='intranet')
        def intranet():
            return 'intranet:' + multi_auth.current_user()

        @app.route('/automation')
        @multi_auth.login_required(role='automation')
        def automation():
            return 'automation:' + multi_auth.current_user()

        @app.route('/reports')
        @multi_auth.login_required(role=('intranet', 'automation'))
        def reports():
            return 'reports:' + multi_auth.current_user()

        @app.route('/intranet-console')
        @multi_auth.login_required(role=(('intranet', 'reports'),))
        def intranet_console():
            return 'intranet_console:' + multi_auth.current_user()

        @app.route('/automation-console')
        @multi_auth.login_required(role=(('automation', 'reports'),))
        def automation_console():
            return 'automation_console:' + multi_auth.current_user()

        self.app = app
        self.client = app.test_client()

    def basic_headers(self, username='svc', password='basic-pass'):
        creds = base64.b64encode('{}:{}'.format(
            username, password).encode('utf-8')).decode('utf-8')
        return {'Authorization': 'Basic ' + creds}

    def digest_headers(self, url, username='svc', password='digest-pass'):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
        header = response.headers['WWW-Authenticate']
        auth_type, auth_info = header.split(None, 1)
        self.assertEqual(auth_type, 'Digest')
        d = parse_dict_header(auth_info)

        a1 = username + ':' + d['realm'] + ':' + password
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:' + url
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':00000001:foobar:auth:' + ha2
        auth_response = md5(a3).hexdigest()

        return {'Authorization':
                'Digest username="{0}",realm="{1}",nonce="{2}",uri="{3}",'
                'qop=auth,nc=00000001,cnonce="foobar",response="{4}",'
                'opaque="{5}"'.format(username, d['realm'], d['nonce'], url,
                                      auth_response, d['opaque'])}

    def test_basic_intranet(self):
        response = self.client.get('/intranet', headers=self.basic_headers())
        self.assertEqual(response.data, b'intranet:svc')
        self.assertEqual(self.principals[-1].scheme, 'Basic')

    def test_basic_automation_denied(self):
        response = self.client.get('/automation',
                                   headers=self.basic_headers())
        self.assertEqual(response.status_code, 403)

    def test_digest_automation(self):
        response = self.client.get('/automation',
                                   headers=self.digest_headers('/automation'))
        self.assertEqual(response.data, b'automation:svc')
        self.assertEqual(self.principals[-1].scheme, 'Digest')

    def test_digest_intranet_denied(self):
        response = self.client.get('/intranet',
                                   headers=self.digest_headers('/intranet'))
        self.assertEqual(response.status_code, 403)

    def test_reports_basic(self):
        response = self.client.get('/reports', headers=self.basic_headers())
        self.assertEqual(response.data, b'reports:svc')

    def test_reports_digest(self):
        response = self.client.get('/reports',
                                   headers=self.digest_headers('/reports'))
        self.assertEqual(response.data, b'reports:svc')

    def test_combined_roles_basic(self):
        response = self.client.get('/intranet-console',
                                   headers=self.basic_headers())
        self.assertEqual(response.data, b'intranet_console:svc')
        response = self.client.get(
            '/automation-console',
            headers=self.basic_headers())
        self.assertEqual(response.status_code, 403)

    def test_combined_roles_digest(self):
        response = self.client.get(
            '/automation-console',
            headers=self.digest_headers('/automation-console'))
        self.assertEqual(response.data, b'automation_console:svc')
        response = self.client.get(
            '/intranet-console',
            headers=self.digest_headers('/intranet-console'))
        self.assertEqual(response.status_code, 403)

    def test_principal_does_not_expose_raw_auth_data(self):
        self.client.get('/reports', headers=self.basic_headers())
        self.client.get('/reports', headers=self.digest_headers('/reports'))
        self.assertEqual(len(self.principals), 2)
        for principal in self.principals:
            self.assertIsInstance(principal, AuthenticatedPrincipal)
            self.assertNotIsInstance(principal, Authorization)
            self.assertEqual(principal.username, 'svc')
            self.assertFalse(hasattr(principal, 'password'))
            self.assertFalse(hasattr(principal, 'token'))
            self.assertFalse(hasattr(principal, 'response'))
        self.assertEqual([p.scheme for p in self.principals],
                         ['Basic', 'Digest'])
