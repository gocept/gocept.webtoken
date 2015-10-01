import gocept.webtoken.keys
import os.path
import shutil
import tempfile
import unittest


class CryptographicKeysTest(unittest.TestCase):

    def setUp(self):
        self.keys_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.keys_dir)

    def test_key_can_be_retrieved(self):
        with open(os.path.join(self.keys_dir, 'jwt-access'), 'w') as f:
            f.write('secret')
        ck = gocept.webtoken.keys.CryptographicKeys(
            self.keys_dir, ['jwt-access'])
        self.assertEqual('secret', ck['jwt-access-private'])

    def test_raises_keyerror_for_unknown_name(self):
        ck = gocept.webtoken.keys.CryptographicKeys(
            self.keys_dir, ['jwt-access'])
        with self.assertRaises(KeyError):
            ck['jwt-access-private']
