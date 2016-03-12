from __future__ import print_function

import sys
import unittest

import keyring.backends.Windows
from ..test_backend import BackendBasicTests

def is_winvault_supported():
    try:
        __import__('win32cred')
        has_pywin32 = True
    except ImportError:
        has_pywin32 = False
    return (
        sys.platform in ['win32'] and sys.getwindowsversion().major >= 6
        and has_pywin32
    )


@unittest.skipUnless(is_winvault_supported(),
                     "Need WinVault")
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
