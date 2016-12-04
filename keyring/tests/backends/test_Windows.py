from __future__ import print_function

import sys
import unittest

import keyring.backends.Windows
from ..test_backend import BackendBasicTests


@unittest.skipUnless(keyring.backends.Windows.WinVaultKeyring.viable,
    "Needs Windows")
class WinVaultKeyringTestCase(BackendBasicTests, unittest.TestCase):
    def tearDown(self):
        # clean up any credentials created
        for cred in self.credentials_created:
            try:
                self.keyring.delete_password(*cred)
            except Exception as e:
                print(e, file=sys.stderr)

    def init_keyring(self):
        return keyring.backends.Windows.WinVaultKeyring()
