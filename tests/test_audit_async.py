import base64
import sys
import unittest
from flask import Flask, g, request
from flask_httpauth import HTTPBasicAuth
import pytest


def basic_creds(username, password):
    creds = base64.b64encode(
        f'{username}:{password}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': 'Basic ' + creds}


@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class HTTPAuthAuditAsyncTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        auth = HTTPBasicAuth()
        self.records = []

        @auth.verify_password
        async def verify_password(username, password):
            if username == 'admin' and password == 'secret':
                return {'name': 'admin'}
            elif username == 'user' and password == 'pass':
                return {'name': 'user'}
            return None

        @auth.get_user_roles
        async def get_user_roles(user):
            return 'admin' if user['name'] == 'admin' else 'user'

        @auth.auth_audit
        async def auth_audit(scheme, result):
            self.records.append({
                'scheme': scheme,
                'result': result,
                'correlation_id': g.get('correlation_id'),
            })

        @app.before_request
        def set_correlation_id():
            g.correlation_id = request.headers.get('X-Correlation-ID')

        @app.route('/button', methods=['POST'])
        @auth.login_required(role='admin')
        async def button():
            if request.form.get('action') == 'explode':
                raise RuntimeError('business failure')
            return 'pressed'

        self.app = app
        self.auth = auth
        self.client = app.test_client()

    def post_button(self, headers, data=None):
        headers = dict(headers)
        headers['X-Correlation-ID'] = 'req-456'
        return self.client.post('/button', headers=headers, data=data or {})

    def test_button_success_audit_order(self):
        response = self.post_button(basic_creds('admin', 'secret'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'pressed')
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-456'},
            {'scheme': 'Basic', 'result': 'success',
             'correlation_id': 'req-456'},
        ])

    def test_button_role_denied_audit_order(self):
        response = self.post_button(basic_creds('user', 'pass'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-456'},
            {'scheme': 'Basic', 'result': 'role_denied',
             'correlation_id': 'req-456'},
        ])

    def test_button_business_exception_audit_order(self):
        with self.assertRaises(RuntimeError):
            self.post_button(basic_creds('admin', 'secret'),
                             data={'action': 'explode'})
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-456'},
        ])

    def test_audit_content_is_limited(self):
        self.post_button(basic_creds('admin', 'secret'))
        self.post_button(basic_creds('user', 'pass'))
        for record in self.records:
            self.assertEqual(set(record.keys()),
                             {'scheme', 'result', 'correlation_id'})


if __name__ == '__main__':
    unittest.main()
