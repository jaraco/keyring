from __future__ import with_statement, absolute_import

from ..py30compat import unittest
from ..test_backend import BackendBasicTests
from keyring.backends import SecretService
from .. import util

need_ss = unittest.skipUnless(SecretService.Keyring.viable,
    "SecretStorage package is needed for SecretServiceKeyring")

class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def init_keyring(self):
        print("Testing SecretServiceKeyring; the following "
            "password prompts are for this keyring")
        return SecretService.Keyring()

SecretServiceKeyringTestCase = need_ss(SecretServiceKeyringTestCase)

class SecretServiceKeyringUnitTests(unittest.TestCase):
    def test_supported_no_secretstorage(self):
        """
        SecretService Keyring is not viable if secretstorage can't be imported.
        """
        with util.NoNoneDictMutator(SecretService.__dict__, secretstorage=None):
            self.assertFalse(SecretService.Keyring.viable)
