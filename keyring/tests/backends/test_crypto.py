import getpass

from ..py30compat import unittest
from ..test_backend import FileKeyringTests

from keyring.backends import file

def is_crypto_supported():
    try:
        __import__('Crypto.Cipher.AES')
        __import__('Crypto.Protocol.KDF')
        __import__('Crypto.Random')
    except ImportError:
        return False
    return True


@unittest.skipUnless(is_crypto_supported(),
                     "Need Crypto module")
class CryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        # patch the getpass module to bypass user input
        self.getpass_orig = getpass.getpass
        getpass.getpass = lambda *args, **kwargs: "abcdef"

    def tearDown(self):
        getpass.getpass = self.getpass_orig
        del self.getpass_orig

    def init_keyring(self):
        return file.EncryptedKeyring()
