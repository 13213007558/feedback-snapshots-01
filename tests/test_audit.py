import base64
import unittest
from flask import Flask, g, request
from flask_httpauth import HTTPBasicAuth


def basic_creds(username, password):
    creds = base64.b64encode(
        f'{username}:{password}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': 'Basic ' + creds}


def create_app(with_audit):
    app = Flask(__name__)
    app.config['TESTING'] = True
    auth = HTTPBasicAuth()
    records = []

    @auth.verify_password
    def verify_password(username, password):
        if username == 'admin' and password == 'secret':
            return {'name': 'admin'}
        elif username == 'user' and password == 'pass':
            return {'name': 'user'}
        return None

    @auth.get_user_roles
    def get_user_roles(user):
        return 'admin' if user['name'] == 'admin' else 'user'

    if with_audit:
        @auth.auth_audit
        def auth_audit(scheme, result):
            records.append({
                'scheme': scheme,
                'result': result,
                'correlation_id': g.get('correlation_id'),
            })

    @app.before_request
    def set_correlation_id():
        g.correlation_id = request.headers.get('X-Correlation-ID')

    @app.route('/button', methods=['POST'])
    @auth.login_required(role='admin')
    def button():
        if request.form.get('action') == 'explode':
            raise RuntimeError('business failure')
        return 'pressed'

    return app, auth, records


class HTTPAuthAuditTestCase(unittest.TestCase):
    def setUp(self):
        self.app, self.auth, self.records = create_app(with_audit=True)
        self.client = self.app.test_client()

    def post_button(self, headers, data=None):
        headers = dict(headers)
        headers['X-Correlation-ID'] = 'req-123'
        return self.client.post('/button', headers=headers, data=data or {})

    def test_button_success_audit_order(self):
        response = self.post_button(basic_creds('admin', 'secret'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'pressed')
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-123'},
            {'scheme': 'Basic', 'result': 'success',
             'correlation_id': 'req-123'},
        ])

    def test_button_role_denied_audit_order(self):
        response = self.post_button(basic_creds('user', 'pass'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-123'},
            {'scheme': 'Basic', 'result': 'role_denied',
             'correlation_id': 'req-123'},
        ])

    def test_button_business_exception_audit_order(self):
        with self.assertRaises(RuntimeError):
            self.post_button(basic_creds('admin', 'secret'),
                             data={'action': 'explode'})
        self.assertEqual(self.records, [
            {'scheme': 'Basic', 'result': 'authenticated',
             'correlation_id': 'req-123'},
        ])

    def test_bad_credentials_not_audited(self):
        response = self.post_button(basic_creds('admin', 'wrong'))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.records, [])

    def test_audit_content_is_limited(self):
        self.post_button(basic_creds('admin', 'secret'))
        self.post_button(basic_creds('user', 'pass'))
        for record in self.records:
            self.assertEqual(set(record.keys()),
                             {'scheme', 'result', 'correlation_id'})

    def test_responses_do_not_change_with_audit(self):
        plain_app, _, _ = create_app(with_audit=False)
        plain_client = plain_app.test_client()

        cases = [
            (basic_creds('admin', 'secret'), {}),
            (basic_creds('user', 'pass'), {}),
            (basic_creds('admin', 'wrong'), {}),
            ({}, {}),
        ]
        for headers, data in cases:
            audited = self.client.post('/button', headers=headers, data=data)
            plain = plain_client.post('/button', headers=headers, data=data)
            self.assertEqual(audited.status_code, plain.status_code)
            self.assertEqual(audited.data, plain.data)
            self.assertEqual(audited.headers.get('WWW-Authenticate'),
                             plain.headers.get('WWW-Authenticate'))


if __name__ == '__main__':
    unittest.main()
