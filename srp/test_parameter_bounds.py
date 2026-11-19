#!/usr/bin/env python
"""Tests for the bounded network-parameter contract of the pure Python backend.

Run with:  python -m unittest srp.test_parameter_bounds
"""

import unittest

import srp._pysrp as _pysrp


TEST_N_HEX = (
    'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4'
    'A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60'
    '95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF'
    '747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907'
    '8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861'
    '60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB'
    'FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'
)

USERNAME = b'alice'
PASSWORD = b'test-only-password'


class ModExpRecorder(object):
    """Replacement for the module's modular-exponentiation choke point."""

    def __init__(self):
        self.calls = []
        self._original = _pysrp._mod_exp

    def __call__(self, base, exponent, modulus):
        self.calls.append((base, exponent, modulus))
        return self._original(base, exponent, modulus)

    def __enter__(self):
        _pysrp._mod_exp = self
        return self

    def __exit__(self, *exc_info):
        _pysrp._mod_exp = self._original
        return False


class ParameterBoundTests(unittest.TestCase):

    def setUp(self):
        self.N, self.g = _pysrp.get_ng(_pysrp.NG_2048, None, None)
        self.salt, self.v = _pysrp.create_salted_verification_key(
            USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        self.user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        self.name, self.A = self.user.start_authentication()

    def assert_rejected(self, category, func, *args, **kwargs):
        with ModExpRecorder() as rec:
            with self.assertRaises(_pysrp.ParameterError) as ctx:
                func(*args, **kwargs)
        self.assertEqual(rec.calls, [], 'modular exponentiation ran before rejection')
        self.assertEqual(str(ctx.exception), 'invalid SRP parameter: %s' % category)
        return ctx.exception

    # -- A -----------------------------------------------------------------

    def test_huge_A_rejected_before_exponentiation(self):
        for value in (b'\x00' * 100000 + b'\x01', b'\x00' * 100000):
            self.assert_rejected(
                'A', _pysrp.Verifier, self.name, self.salt, self.v,
                value, _pysrp.SHA256, _pysrp.NG_2048)

    def test_A_above_group_rejected_before_exponentiation(self):
        self.assert_rejected(
            'A', _pysrp.Verifier, self.name, self.salt, self.v,
            _pysrp.long_to_bytes(self.N + 1), _pysrp.SHA256, _pysrp.NG_2048)

    def test_zero_and_multiple_of_N_still_abort_without_exponentiation(self):
        for value in (b'\x00' * 16, _pysrp.long_to_bytes(2 * self.N)):
            with ModExpRecorder() as rec:
                verifier = _pysrp.Verifier(
                    self.name, self.salt, self.v, value,
                    _pysrp.SHA256, _pysrp.NG_2048)
            self.assertTrue(verifier.safety_failed)
            self.assertEqual(verifier.get_challenge(), (None, None))
            self.assertEqual(rec.calls, [])
            # A caller echoing the failure sentinel must not authenticate.
            self.assertIsNone(verifier.verify_session(None))
            self.assertFalse(verifier.authenticated())

    def test_leading_zero_A_is_accepted(self):
        padded = b'\x00' * 8 + _pysrp.long_to_bytes(
            _pysrp.bytes_to_long(self.A))
        verifier = _pysrp.Verifier(
            self.name, self.salt, self.v, padded,
            _pysrp.SHA256, _pysrp.NG_2048)
        self.assertFalse(verifier.safety_failed)
        s, B = verifier.get_challenge()
        proof = self.user.process_challenge(s, B)
        self.assertIsNotNone(proof)
        self.assertIsNotNone(verifier.verify_session(proof))
        self.user.verify_session(verifier.H_AMK)
        self.assertTrue(self.user.authenticated())
        self.assertTrue(verifier.authenticated())

    def test_too_many_leading_zero_bytes_rejected(self):
        padded = b'\x00' * 9 + _pysrp.long_to_bytes(_pysrp.bytes_to_long(self.A))
        self.assert_rejected(
            'A', _pysrp.Verifier, self.name, self.salt, self.v,
            padded, _pysrp.SHA256, _pysrp.NG_2048)

    def test_late_A_is_bounded_before_exponentiation(self):
        verifier = _pysrp.Verifier(
            self.name, self.salt, self.v, None, _pysrp.SHA256, _pysrp.NG_2048)
        with ModExpRecorder() as rec:
            with self.assertRaises(_pysrp.ParameterError) as ctx:
                verifier.verify_session(b'\x00' * 32, b'\x01' * 100000)
        self.assertEqual(rec.calls, [])
        self.assertEqual(str(ctx.exception), 'invalid SRP parameter: A')

    def test_user_supplied_A_is_bounded(self):
        self.assert_rejected(
            'A', _pysrp.User, USERNAME, PASSWORD, _pysrp.SHA256,
            _pysrp.NG_2048, None, None, None, b'\x01' * 100000)

    # -- B -----------------------------------------------------------------

    def test_huge_B_rejected_before_exponentiation(self):
        user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        user.start_authentication()
        self.assert_rejected(
            'B', user.process_challenge, self.salt, b'\x01' * 100000)

    def test_B_above_group_rejected_before_exponentiation(self):
        user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        user.start_authentication()
        self.assert_rejected(
            'B', user.process_challenge, self.salt,
            _pysrp.long_to_bytes(self.N + 1))

    def test_zero_and_multiple_B_return_none_without_exponentiation(self):
        for value in (b'\x00' * 16, _pysrp.long_to_bytes(2 * self.N)):
            user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
            user.start_authentication()
            with ModExpRecorder() as rec:
                self.assertIsNone(user.process_challenge(self.salt, value))
            self.assertEqual(rec.calls, [])
            user.verify_session(None)
            self.assertFalse(user.authenticated())

    # -- verifier ----------------------------------------------------------

    def test_bad_verifier_rejected_before_exponentiation(self):
        cases = [
            b'\x00' * 16,
            _pysrp.long_to_bytes(2 * self.N),
            _pysrp.long_to_bytes(self.N + 1),
            b'\x01' * 100000,
        ]
        for value in cases:
            self.assert_rejected(
                'verifier', _pysrp.Verifier, self.name, self.salt, value,
                None, _pysrp.SHA256, _pysrp.NG_2048)

    def test_verifier_leading_zeros_accepted(self):
        verifier = _pysrp.Verifier(
            self.name, self.salt, b'\x00' * 8 + self.v,
            self.A, _pysrp.SHA256, _pysrp.NG_2048)
        self.assertFalse(verifier.safety_failed)
        s, B = verifier.get_challenge()
        proof = self.user.process_challenge(s, B)
        self.assertIsNotNone(verifier.verify_session(proof))
        self.user.verify_session(verifier.H_AMK)
        self.assertTrue(verifier.authenticated())
        self.assertTrue(self.user.authenticated())

    # -- custom group ------------------------------------------------------

    def test_custom_group_is_length_bounded(self):
        self.assert_rejected('N', _pysrp.get_ng, _pysrp.NG_CUSTOM,
                             'f' * 100000, '2')

    def test_custom_group_rejects_tiny_modulus(self):
        self.assert_rejected('N', _pysrp.get_ng, _pysrp.NG_CUSTOM, '3', '2')

    def test_custom_group_rejects_out_of_range_generator(self):
        self.assert_rejected('g', _pysrp.get_ng, _pysrp.NG_CUSTOM,
                             TEST_N_HEX, TEST_N_HEX)

    def test_oversized_k_declaration_rejected(self):
        self.assert_rejected(
            'k', _pysrp.User, USERNAME, PASSWORD, _pysrp.SHA256,
            _pysrp.NG_2048, None, None, None, None, b'f' * 100000)

    def test_custom_group_positive_handshake(self):
        salt, v = _pysrp.create_salted_verification_key(
            USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_CUSTOM,
            TEST_N_HEX, '2')
        user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256,
                           _pysrp.NG_CUSTOM, TEST_N_HEX, '2')
        name, A = user.start_authentication()
        verifier = _pysrp.Verifier(name, salt, v, A, _pysrp.SHA256,
                                   _pysrp.NG_CUSTOM, TEST_N_HEX, '2')
        s, B = verifier.get_challenge()
        proof = user.process_challenge(s, B)
        self.assertIsNotNone(verifier.verify_session(proof))
        user.verify_session(verifier.H_AMK)
        self.assertTrue(user.authenticated())
        self.assertTrue(verifier.authenticated())

    # -- fixed 2048-bit group ---------------------------------------------

    def test_real_2048_group_positive_handshake(self):
        salt, v = _pysrp.create_salted_verification_key(
            USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        user = _pysrp.User(USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        name, A = user.start_authentication()
        with ModExpRecorder() as rec:
            verifier = _pysrp.Verifier(name, salt, v, A, _pysrp.SHA256,
                                       _pysrp.NG_2048)
            s, B = verifier.get_challenge()
            proof = user.process_challenge(s, B)
            confirmation = verifier.verify_session(proof)
        self.assertTrue(rec.calls, 'positive path should perform exponentiation')
        self.assertIsNotNone(confirmation)
        user.verify_session(confirmation)
        self.assertTrue(user.authenticated())
        self.assertTrue(verifier.authenticated())

    def test_wrong_password_still_fails_real_group(self):
        salt, v = _pysrp.create_salted_verification_key(
            USERNAME, PASSWORD, _pysrp.SHA256, _pysrp.NG_2048)
        user = _pysrp.User(USERNAME, b'wrong-password', _pysrp.SHA256,
                           _pysrp.NG_2048)
        name, A = user.start_authentication()
        verifier = _pysrp.Verifier(name, salt, v, A, _pysrp.SHA256,
                                   _pysrp.NG_2048)
        s, B = verifier.get_challenge()
        proof = user.process_challenge(s, B)
        self.assertIsNone(verifier.verify_session(proof))
        self.assertFalse(verifier.authenticated())
        self.assertFalse(user.authenticated())

    # -- error text --------------------------------------------------------

    def test_error_text_does_not_echo_secrets(self):
        user = _pysrp.User(USERNAME, b'unique-secret-passphrase',
                           _pysrp.SHA256, _pysrp.NG_2048)
        user.start_authentication()
        value = b'\x01' * 300
        with self.assertRaises(_pysrp.ParameterError) as ctx:
            user.process_challenge(self.salt, value)
        message = str(ctx.exception)
        self.assertEqual(message, 'invalid SRP parameter: B')
        self.assertNotIn('unique-secret-passphrase', message)
        self.assertNotIn(self.salt.hex(), message)
        self.assertNotIn(value.hex(), message)


if __name__ == '__main__':
    unittest.main()
