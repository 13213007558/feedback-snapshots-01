import base64
import unittest
from datetime import datetime, timedelta, timezone

from examples.basic_to_token_migration import app, db


def basic_header(username, password):
    creds = base64.b64encode(
        f'{username}:{password}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': 'Basic ' + creds}


def bearer_header(token):
    return {'Authorization': 'Bearer ' + token}


class BasicToTokenMigrationTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_legacy_client_with_valid_password(self):
        response = self.client.get('/', headers=basic_header('john', 'hello'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(),
                         {'user': 'john', 'auth_method': 'basic'})

    def test_modern_client_with_valid_token(self):
        response = self.client.get('/', headers=bearer_header('token-for-jane'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(),
                         {'user': 'jane', 'auth_method': 'token'})

    def test_legacy_client_with_wrong_password(self):
        response = self.client.get('/', headers=basic_header('john', 'nope'))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_modern_client_with_unknown_token(self):
        response = self.client.get('/', headers=bearer_header('bad-token'))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    def test_modern_client_with_revoked_token(self):
        token_hash = db['tokens'].keys()
        record = db['tokens'][next(iter(token_hash))]
        record['revoked'] = True
        try:
            response = self.client.get('/',
                                       headers=bearer_header('token-for-jane'))
            self.assertEqual(response.status_code, 401)
        finally:
            record['revoked'] = False

    def test_modern_client_with_expired_token(self):
        record = db['tokens'][next(iter(db['tokens']))]
        original = record['expires_at']
        record['expires_at'] = datetime.now(timezone.utc) - timedelta(days=1)
        try:
            response = self.client.get('/',
                                       headers=bearer_header('token-for-jane'))
            self.assertEqual(response.status_code, 401)
        finally:
            record['expires_at'] = original

    def test_no_credentials_challenges_with_basic(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_token_issuance_over_basic(self):
        response = self.client.post('/tokens',
                                    headers=basic_header('john', 'hello'))
        self.assertEqual(response.status_code, 200)
        token = response.get_json()['token']
        response = self.client.get('/', headers=bearer_header(token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(),
                         {'user': 'john', 'auth_method': 'token'})

    def test_token_issuance_rejects_bad_password(self):
        response = self.client.post('/tokens',
                                    headers=basic_header('john', 'nope'))
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
