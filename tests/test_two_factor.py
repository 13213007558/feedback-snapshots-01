import base64
import unittest
from flask import Flask, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        service_auth = HTTPBasicAuth()
        otp_auth = HTTPTokenAuth(header='X-OTP')

        services = {'billing-service': 'service-secret'}
        one_time_passwords = {'alice': '424242', 'bob': '909090'}

        @service_auth.verify_password
        def verify_service(username, password):
            if username in services and services[username] == password:
                g.two_factor_service = {'service_id': username}
                return username
            return None

        @otp_auth.verify_token
        def verify_otp(token):
            for operator, otp in one_time_passwords.items():
                if otp == token:
                    g.two_factor_operator = {
                        'operator': operator, 'otp': token}
                    return operator
            return None

        @service_auth.error_handler
        def service_auth_error(status):
            return 'service auth error', status

        @otp_auth.error_handler
        def otp_auth_error(status):
            return 'otp auth error', status

        @app.route('/public')
        def public():
            return 'public'

        @app.route('/service-only')
        @service_auth.login_required
        def service_only():
            return 'service:' + g.two_factor_service['service_id']

        @app.route('/operator-only')
        @otp_auth.login_required
        def operator_only():
            return 'operator:' + g.two_factor_operator['operator']

        @app.route('/restricted')
        @service_auth.login_required
        @otp_auth.login_required
        def restricted():
            return 'restricted:{}|{}'.format(
                g.two_factor_service['service_id'],
                g.two_factor_operator['operator'])

        self.app = app
        self.client = app.test_client()
        self.basic_headers = {
            'Authorization': 'Basic ' + base64.b64encode(
                b'billing-service:service-secret').decode('utf-8')}
        self.otp_headers = {'X-OTP': '424242'}

    def test_public_needs_no_auth(self):
        response = self.client.get('/public')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'public')

    def test_restricted_prompts_without_any_proof(self):
        response = self.client.get('/restricted')
        self.assertEqual(response.status_code, 401)

    def test_restricted_rejects_basic_alone(self):
        response = self.client.get('/restricted', headers=self.basic_headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.decode('utf-8'), 'otp auth error')

    def test_restricted_rejects_otp_alone(self):
        response = self.client.get('/restricted', headers=self.otp_headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.decode('utf-8'), 'service auth error')

    def test_restricted_rejects_when_both_proofs_are_invalid(self):
        response = self.client.get(
            '/restricted',
            headers={
                'Authorization': 'Basic ' + base64.b64encode(
                    b'billing-service:wrong-secret').decode('utf-8'),
                'X-OTP': '000000'})
        self.assertEqual(response.status_code, 401)

    def test_restricted_rejects_valid_otp_with_bad_service(self):
        response = self.client.get(
            '/restricted',
            headers={
                'Authorization': 'Basic ' + base64.b64encode(
                    b'billing-service:wrong-secret').decode('utf-8'),
                'X-OTP': '424242'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.decode('utf-8'), 'service auth error')

    def test_restricted_rejects_valid_service_with_bad_otp(self):
        response = self.client.get(
            '/restricted',
            headers={
                'Authorization': self.basic_headers['Authorization'],
                'X-OTP': '000000'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.decode('utf-8'), 'otp auth error')

    def test_restricted_grants_access_with_both_proofs(self):
        response = self.client.get(
            '/restricted',
            headers=dict(self.basic_headers, **self.otp_headers))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode('utf-8'),
            'restricted:billing-service|alice')

    def test_each_factor_keeps_its_own_identity(self):
        response = self.client.get(
            '/restricted',
            headers={'Authorization': self.basic_headers['Authorization'],
                     'X-OTP': '909090'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode('utf-8'),
            'restricted:billing-service|bob')

    def test_single_factor_endpoints_remain_available(self):
        response = self.client.get(
            '/service-only', headers=self.basic_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode('utf-8'), 'service:billing-service')

        response = self.client.get('/operator-only', headers=self.otp_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode('utf-8'), 'operator:alice')
