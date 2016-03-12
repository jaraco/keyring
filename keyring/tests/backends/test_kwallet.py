import unittest

from keyring.backends import kwallet
from ..test_backend import BackendBasicTests


@unittest.skipUnless(kwallet.DBusKeyring.viable, "Need DBus")
class DBusKWalletTestCase(BackendBasicTests, unittest.TestCase):

    def init_keyring(self):
        return kwallet.DBusKeyring()
