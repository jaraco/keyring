import os
import sys

from ..py30compat import unittest
from ..test_backend import BackendBasicTests
from keyring.backends import SecretService
from ..util import ImportKiller, Environ

def is_dbus_supported():
    try:
        __import__('dbus')
    except ImportError:
        return False
    return 'DISPLAY' in os.environ

@unittest.skipUnless(is_dbus_supported(),
    "DBus needed for SecretServiceKeyring")
class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def environ(self):
        return dict(DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        print >> sys.stderr, "Testing SecretServiceKeyring, following password prompts are for this keyring"
        return SecretService.Keyring()

    def test_supported_no_module(self):
        with ImportKiller('dbus'):
            with Environ(**self.environ()):
                self.assertEqual(-1, self.keyring.supported())
