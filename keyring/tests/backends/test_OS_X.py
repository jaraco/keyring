import sys

from ..test_backend import BackendBasicTests
from ..py30compat import unittest
from keyring.backends import OS_X

def is_osx_keychain_supported():
    return sys.platform in ('mac','darwin')

need_osx = unittest.skipUnless(is_osx_keychain_supported(),
                     "Need OS X")
class OSXKeychainTestCase(BackendBasicTests, unittest.TestCase):

    def init_keyring(self):
        return OS_X.Keyring()

    @unittest.expectedFailure
    def test_delete_present(self):
        """Not implemented"""
        super(OSXKeychainTestCase, self).test_delete_present()

OSXKeychainTestCase = need_osx(OSXKeychainTestCase)

def test_SecurityCommand():
    assert OS_X.SecurityCommand('get') == 'get-generic-password'
    assert OS_X.SecurityCommand('set', 'internet') == 'set-internet-password'
