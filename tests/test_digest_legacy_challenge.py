import unittest
from hashlib import md5 as _md5

from flask import Flask
from flask_httpauth import HTTPDigestAuth
from werkzeug.http import parse_dict_header


def md5(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return _md5(value).hexdigest()


class FixedClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def digest_authorization(path, realm, nonce, opaque, username='susan',
                         password='hello'):
    ha1 = md5(f'{username}:{realm}:{password}')
    ha2 = md5(f'GET:{path}')
    response_hash = md5(f'{ha1}:{nonce}:{ha2}')
    return (
        f'Digest username="{username}",realm="{realm}",'
        f'nonce="{nonce}",uri="{path}",response="{response_hash}",'
        f'opaque="{opaque}"'
    )


class HTTPDigestLegacyChallengeTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        self.clock = FixedClock()
        self.current_nonces = set()
        self.current_opaques = set()
        self.scada_legacy_nonces = {'scada-legacy-nonce'}
        self.scada_legacy_opaques = {'scada-legacy-opaque'}
        self.hmi_legacy_nonces = {'hmi-legacy-nonce'}
        self.hmi_legacy_opaques = {'hmi-legacy-opaque'}

        scada_auth = HTTPDigestAuth(realm='scada', qop=None)
        hmi_auth = HTTPDigestAuth(realm='hmi', qop=None)

        @scada_auth.get_password
        @hmi_auth.get_password
        def get_digest_password(username):
            if username == 'susan':
                return 'hello'
            if username == 'john':
                return 'bye'
            return None

        @scada_auth.generate_nonce
        def generate_scada_nonce():
            nonce = md5(f'scada-current-nonce:{len(self.current_nonces)}')
            self.current_nonces.add(nonce)
            return nonce

        @scada_auth.verify_nonce
        def verify_scada_nonce(nonce):
            return nonce in self.current_nonces

        @scada_auth.generate_opaque
        def generate_scada_opaque():
            opaque = md5(f'scada-current-opaque:{len(self.current_opaques)}')
            self.current_opaques.add(opaque)
            return opaque

        @scada_auth.verify_opaque
        def verify_scada_opaque(opaque):
            return opaque in self.current_opaques

        @hmi_auth.generate_nonce
        def generate_hmi_nonce():
            return 'hmi-current-nonce'

        @hmi_auth.verify_nonce
        def verify_hmi_nonce(nonce):
            return nonce == 'hmi-current-nonce'

        @hmi_auth.generate_opaque
        def verify_hmi_generate_opaque():
            return 'hmi-current-opaque'

        @hmi_auth.verify_opaque
        def verify_hmi_opaque(opaque):
            return opaque == 'hmi-current-opaque'

        scada_auth.add_legacy_challenge(
            self.scada_legacy_nonces.__contains__,
            verify_opaque=self.scada_legacy_opaques.__contains__,
            ttl=300, clock=self.clock)
        hmi_auth.add_legacy_challenge(
            self.hmi_legacy_nonces.__contains__,
            verify_opaque=self.hmi_legacy_opaques.__contains__,
            ttl=300, clock=self.clock)

        @app.route('/scada')
        @scada_auth.login_required
        def scada_route():
            return 'scada:' + scada_auth.username()

        @app.route('/hmi')
        @hmi_auth.login_required
        def hmi_route():
            return 'hmi:' + hmi_auth.username()

        self.app = app
        self.scada_auth = scada_auth
        self.hmi_auth = hmi_auth
        self.client = app.test_client()

    def test_new_challenge_is_accepted(self):
        response = self.client.get('/scada')
        self.assertEqual(response.status_code, 401)
        challenge = parse_dict_header(
            response.headers['WWW-Authenticate'].split(None, 1)[1])
        self.assertEqual(challenge['realm'], 'scada')
        self.assertIn(challenge['nonce'], self.current_nonces)

        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', challenge['realm'], challenge['nonce'],
                challenge['opaque'])})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'scada:susan')

    def test_legacy_challenge_within_window_is_accepted(self):
        self.clock.now = 1100.0
        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'scada', 'scada-legacy-nonce',
                'scada-legacy-opaque')})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'scada:susan')

    def test_legacy_challenge_is_rejected_after_window_expires(self):
        self.clock.now = 1300.0
        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'scada', 'scada-legacy-nonce',
                'scada-legacy-opaque')})
        self.assertEqual(response.status_code, 401)

        header = response.headers.get('WWW-Authenticate')
        self.assertIsNotNone(header)
        challenge = parse_dict_header(header.split(None, 1)[1])
        self.assertEqual(challenge['realm'], 'scada')
        # the failure response offers a fresh challenge from the new
        # configuration, so legal clients can re-authenticate
        self.assertIn(challenge['nonce'], self.current_nonces)
        self.assertIn(challenge['opaque'], self.current_opaques)

        retry = digest_authorization(
            '/scada', challenge['realm'], challenge['nonce'],
            challenge['opaque'])
        response = self.client.get(
            '/scada', headers={'Authorization': retry})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'scada:susan')

    def test_legacy_challenge_is_rejected_by_other_realm(self):
        self.clock.now = 1100.0
        response = self.client.get(
            '/hmi', headers={'Authorization': digest_authorization(
                '/hmi', 'scada', 'scada-legacy-nonce',
                'scada-legacy-opaque')})
        self.assertEqual(response.status_code, 401)
        header = response.headers.get('WWW-Authenticate')
        self.assertIsNotNone(header)
        challenge = parse_dict_header(header.split(None, 1)[1])
        self.assertEqual(challenge['realm'], 'hmi')
        self.assertEqual(challenge['nonce'], 'hmi-current-nonce')

        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'hmi', 'hmi-legacy-nonce',
                'hmi-legacy-opaque')})
        self.assertEqual(response.status_code, 401)
        challenge = parse_dict_header(
            response.headers['WWW-Authenticate'].split(None, 1)[1])
        self.assertEqual(challenge['realm'], 'scada')

    def test_legacy_opaque_mismatch_is_rejected(self):
        self.clock.now = 1100.0
        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'scada', 'scada-legacy-nonce',
                'forged-opaque')})
        self.assertEqual(response.status_code, 401)
        challenge = parse_dict_header(
            response.headers['WWW-Authenticate'].split(None, 1)[1])
        self.assertIn(challenge['nonce'], self.current_nonces)

    def test_legacy_challenge_with_absolute_expiration(self):
        absolute_nonces = {'scada-absolute-nonce'}
        absolute_opaques = {'scada-absolute-opaque'}
        self.scada_auth.add_legacy_challenge(
            absolute_nonces.__contains__,
            verify_opaque=absolute_opaques.__contains__,
            expires_at=1150.0, clock=self.clock)

        self.clock.now = 1140.0
        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'scada', 'scada-absolute-nonce',
                'scada-absolute-opaque')})
        self.assertEqual(response.status_code, 200)

        self.clock.now = 1160.0
        response = self.client.get(
            '/scada', headers={'Authorization': digest_authorization(
                '/scada', 'scada', 'scada-absolute-nonce',
                'scada-absolute-opaque')})
        self.assertEqual(response.status_code, 401)

    def test_legacy_registration_rejects_foreign_realm(self):
        with self.assertRaises(ValueError):
            self.scada_auth.add_legacy_challenge(
                self.scada_legacy_nonces.__contains__,
                realm='hmi', ttl=300, clock=self.clock)

    def test_legacy_registration_requires_single_window(self):
        with self.assertRaises(ValueError):
            self.scada_auth.add_legacy_challenge(
                self.scada_legacy_nonces.__contains__, clock=self.clock)
        with self.assertRaises(ValueError):
            self.scada_auth.add_legacy_challenge(
                self.scada_legacy_nonces.__contains__, ttl=300,
                expires_at=2000.0, clock=self.clock)

    def test_legacy_challenge_with_default_clock(self):
        default_nonces = {'default-legacy-nonce'}
        default_opaques = {'default-legacy-opaque'}
        default_auth = HTTPDigestAuth(realm='default', qop=None)

        @default_auth.get_password
        def get_default_password(username):
            return 'hello' if username == 'susan' else None

        @default_auth.generate_nonce
        def generate_default_nonce():
            return 'default-current-nonce'

        @default_auth.verify_nonce
        def verify_default_nonce(nonce):
            return nonce == 'default-current-nonce'

        @default_auth.generate_opaque
        def generate_default_opaque():
            return 'default-current-opaque'

        @default_auth.verify_opaque
        def verify_default_opaque(opaque):
            return opaque == 'default-current-opaque'

        default_auth.add_legacy_challenge(
            default_nonces.__contains__,
            verify_opaque=default_opaques.__contains__,
            ttl=-1)

        @self.app.route('/default')
        @default_auth.login_required
        def default_route():
            return 'default:' + default_auth.username()

        response = self.client.get(
            '/default', headers={'Authorization': digest_authorization(
                '/default', 'default', 'default-legacy-nonce',
                'default-legacy-opaque')})
        self.assertEqual(response.status_code, 401)
        challenge = parse_dict_header(
            response.headers['WWW-Authenticate'].split(None, 1)[1])
        self.assertEqual(challenge['nonce'], 'default-current-nonce')
