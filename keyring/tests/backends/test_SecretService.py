import os
import sys

from ..py30compat import unittest
from ..test_backend import BackendBasicTests
from keyring.backends import SecretService
from ..util import ImportKiller

def is_secretstorage_supported():
    try:
        __import__('secretstorage')
    except ImportError:
        return False
    return 'DISPLAY' in os.environ

@unittest.skipUnless(is_secretstorage_supported(),
    "SecretStorage package is needed for SecretServiceKeyring")
class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, ("Testing SecretServiceKeyring; the following "
            "password prompts are for this keyring")
        return SecretService.Keyring()

class SecretServiceKeyringUnitTests(unittest.TestCase):
    def test_supported_no_dbus(self):
        """
        SecretService Keyring is not supported if dbus can't be imported.
        """
        with ImportKiller('dbus'):
            self.assertEqual(-1, SecretService.Keyring().supported())

    def test_supported_no_secretstorage(self):
        """
        SecretService Keyring is not supported if secretstorage can't be imported.
        """
        with ImportKiller('secretstorage'):
            self.assertEqual(-1, SecretService.Keyring().supported())
