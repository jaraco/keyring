import sys

import pytest

import keyring.backends.Windows
from keyring.testing.backend import BackendBasicTests, UNICODE_CHARS


@pytest.mark.skipif(
    not keyring.backends.Windows.WinVaultKeyring.viable, reason="Needs Windows"
)
class TestWinVaultKeyring(BackendBasicTests):
    def tearDown(self):
        # clean up any credentials created
        for cred in self.credentials_created:
            try:
                self.keyring.delete_password(*cred)
            except Exception as e:
                print(e, file=sys.stderr)

    def init_keyring(self):
        return keyring.backends.Windows.WinVaultKeyring()

    def test_read_utf8_password(self):
        """
        Write a UTF-8 encoded credential and make sure it can be read back correctly.
        """
        service = "keyring-utf8-test"
        username = "keyring"
        password = "utf8-test" + UNICODE_CHARS

        self.keyring.set_password(service, username, password)
        assert self.keyring.get_password(service, username) == password

    def test_long_password_nice_error(self):
        self.keyring.set_password('system', 'user', 'x' * 10000)
        self.keyring.delete_password('system', 'user')

    def test_long_password_too_long_nice_error(self):
        try:
            self.keyring.set_password('system', 'user', 'x' * (2**20 + 1))
            self.keyring.delete_password('system', 'user')
        except ValueError as e:
            if e.args[0] == 2**20:
                assert True
            else:
                assert False
        except Exception:
            assert False


@pytest.mark.skipif('sys.platform != "win32"')
def test_winvault_always_viable():
    """
    The WinVault backend should always be viable on Windows.
    """
    assert keyring.backends.Windows.WinVaultKeyring.viable
