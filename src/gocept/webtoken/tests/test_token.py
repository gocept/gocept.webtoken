import gocept.webtoken.testing
import unittest


class CreateWebTokenDecodeWebTokenTests(unittest.TestCase):
    """Testing ..token.create_web_token and ..token.decode_webtoken."""

    layer = gocept.webtoken.testing.KEYS_LAYER

    def create_token(
            self, key_name, subject, data=None, expires_in=None):
        from ..token import create_web_token
        return create_web_token(key_name, 'issuer', subject, expires_in, data)

    def decode_token(self, token, key_name, subject):
        from ..token import decode_web_token
        return decode_web_token(token['token'], key_name, subject)

    def test_raises_ValueError_on_invalid_token(self):
        with self.assertRaises(ValueError) as err:
            self.decode_token(
                {'token': 'asdf'}, 'jwt-application-public', 'asdf')
        self.assertEqual('Not enough segments', str(err.exception))

    def test_raises_ValueError_on_wrong_cryptographic_key(self):
        token = self.create_token('jwt-application-private', 'app')
        with self.assertRaises(ValueError) as err:
            self.decode_token(token, 'jwt-access-public', 'app')
        self.assertEqual('Signature verification failed', str(err.exception))

    def test_raises_ValueError_on_expired_token(self):
        token = self.create_token('jwt-access-private', 'app', expires_in=-1)
        with self.assertRaises(ValueError) as err:
            self.decode_token(token, 'jwt-access-public', 'app')
        self.assertEqual('Signature has expired', str(err.exception))

    def test_raises_ValueError_on_invalid_subject(self):
        token = self.create_token('jwt-access-private', 'app')
        with self.assertRaises(ValueError) as err:
            self.decode_token(token, 'jwt-access-public', 'access')
        self.assertEqual(
            "Subject mismatch 'access' != u'app'", str(err.exception))

    def test_returns_decoded_token_contend_if_valid(self):
        token = self.create_token(
            'jwt-access-private', 'app', data={'foo': 'bar'})
        decoded = self.decode_token(token, 'jwt-access-public', 'app')
        self.assertItemsEqual([u'iss', u'iat', u'data', u'sub', u'nbf'],
                              decoded.keys())
        self.assertEqual('issuer', decoded['iss'])
        self.assertEqual({u'foo': u'bar'}, decoded['data'])
        # iat, nbf and exp have been checked implicitly by validation upon
        # decoding

    def test_create_web_token_returns_encoded_token_and_token_contents(self):
        token = self.create_token(
            'jwt-access-private', 'app', data={'foo': 'bar'})
        self.assertEqual(
            token['data'],
            self.decode_token(token, 'jwt-access-public', 'app'))
