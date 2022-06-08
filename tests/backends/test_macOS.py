import pytest

import keyring
from keyring.testing.backend import BackendBasicTests
from keyring.backends import macOS


@pytest.mark.skipif(
    not keyring.backends.macOS.Keyring.viable,
    reason="macOS backend not viable",
)
class Test_macOSKeychain(BackendBasicTests):
    def init_keyring(self):
        return macOS.Keyring()

    def test_alternate_keychain(self):
        alt = self.keyring.with_keychain('abcd')
        assert alt.keychain == 'abcd'
        assert self.keyring.keychain != 'abcd'
