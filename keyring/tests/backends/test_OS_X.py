import sys
import unittest

from ..test_backend import BackendBasicTests
from keyring.backends import OS_X

def is_osx_keychain_supported():
    return sys.platform in ('mac','darwin')

@unittest.skipUnless(is_osx_keychain_supported(),
                     "Need OS X")
class OSXKeychainTestCase(BackendBasicTests, unittest.TestCase):

    def init_keyring(self):
        return OS_X.Keyring()

class SecurityCommandTestCase(unittest.TestCase):
    def test_SecurityCommand(self):
        self.assertEqual(OS_X.SecurityCommand('get'), 'get-generic-password')
        self.assertEqual(OS_X.SecurityCommand('set', 'internet'), 'set-internet-password')
