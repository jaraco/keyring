import pytest

import keyring
from keyring.backends import macOS
from keyring.testing.backend import BackendBasicTests


@pytest.mark.skipif(
    not keyring.backends.macOS.Keyring.viable,
    reason="macOS backend not viable",
)
class Test_macOSKeychain(BackendBasicTests):
    def init_keyring(self):
        return macOS.Keyring()
