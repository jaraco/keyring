import unittest

from ..test_backend import BackendBasicTests
from keyring.backends import SecretService
from .. import util


@unittest.skipUnless(SecretService.Keyring.viable,
                     "SecretStorage package is needed for SecretServiceKeyring")
class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def init_keyring(self):
        print("Testing SecretServiceKeyring; the following "
              "password prompts are for this keyring")
        keyring = SecretService.Keyring()
        keyring.preferred_collection = '/org/freedesktop/secrets/collection/session'
        return keyring


class SecretServiceKeyringUnitTests(unittest.TestCase):
    def test_supported_no_secretstorage(self):
        """
        SecretService Keyring is not viable if secretstorage can't be imported.
        """
        with util.NoNoneDictMutator(SecretService.__dict__, secretstorage=None):
            self.assertFalse(SecretService.Keyring.viable)
