import sys

import pytest

from keyring.testing.backend import BackendBasicTests
from keyring.backends import OS_X


def is_osx_keychain_supported():
    return sys.platform in ('mac', 'darwin')


@pytest.mark.skipif(not is_osx_keychain_supported(), reason="Needs macOS")
class OSXKeychainTestCase(BackendBasicTests):
    def init_keyring(self):
        return OS_X.Keyring()
