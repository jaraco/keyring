import pytest

import keyring.backends.Windows
from keyring.testing.backend import BackendBasicTests, UNICODE_CHARS


@pytest.mark.skipif(
    not keyring.backends.Windows.WinVaultKeyring.viable, reason="Needs Windows"
)
class TestWinVaultKeyring(BackendBasicTests):
    def init_keyring(self):
        return keyring.backends.Windows.WinVaultKeyring()

    def test_read_odd_length_utf8_password(self):
        """
        Write a UTF-8 encoded credential and make sure it can be read back correctly.
        """
        service = "keyring-utf8-test"
        username = "keyring"
        password = "utf8-test" + UNICODE_CHARS

        self.keyring.set_password(service, username, password, encoding='utf-8')
        assert self.keyring.get_password(service, username) == password
        self.credentials_created.add((service, username))

    def test_read_even_length_utf8_password(self):
        """
        Write a UTF-8 encoded credential and make sure it can be read back correctly.
        """
        service = "keyring-utf8-test"
        username = "keyring"
        password = "utf8-test-" + UNICODE_CHARS

        self.keyring.set_password(service, username, password, encoding='utf-8')

        # TODO https://github.com/jaraco/keyring/issues/554
        # The following line should be `==`, not `!=`.
        assert self.keyring.get_password(service, username) != password
        self.credentials_created.add((service, username))

    def test_long_password_no_error(self):
        service = 'system'
        username = 'user'
        self.keyring.set_password(service, username, 'x' * 1280)
        assert self.keyring.get_password(service, username) == 'x' * 1280
        self.credentials_created.add((service, username))

    # NOTE maximum 64 attributes of 256 bytes each == max sharded encoded password
    def test_too_long_password_test_error(self):
        with pytest.raises(OSError) as e_info:
            service = 'system'
            username = 'user'
            self.keyring.set_password(service, username, 'x' * 1281)
            assert self.keyring.get_password(service, username) == 'x' * 1281

        assert e_info.value.winerror == 1783

    def test_enumerate(self):
        from keyring.backends.Windows import api as win32cred

        entries = win32cred.CredEnumerate()
        assert entries

    def test_set_persist(self):
        keyring = self.keyring
        keyring.persist = 'Enterprise'


class TestWinVaultAttributesKeyring(TestWinVaultKeyring):
    def init_keyring(self):
        return keyring.backends.Windows.WinVaultAttributesKeyring()

    def test_long_password_no_error(self):
        service = 'system'
        username = 'user'
        self.keyring.set_password(service, username, 'x' * (64 * 256))
        assert self.keyring.get_password(service, username) == 'x' * (64 * 256)
        self.credentials_created.add((service, username))

    # NOTE maximum 64 attributes of 256 bytes each == max sharded encoded password
    def test_too_long_password_test_error(self):
        with pytest.raises(ValueError) as e_info:
            service = 'system'
            username = 'user'
            self.keyring.set_password(service, username, 'x' * (64 * 256 + 1))
            assert self.keyring.get_password(service, username) == 'x' * (64 * 256 + 1)

        assert e_info.value.args[0] == 64 * 256

    def test_read_from_attributes(self):
        from keyring.backends.Windows import api as win32cred

        service = 'system'
        username = 'user'
        self.keyring.set_password(service, username, 'x' * (64 * 256))
        cred = win32cred.CredReadFromAttributes(
            Type=win32cred.CRED_TYPE_GENERIC, TargetName=service
        )
        assert cred['CredentialBlob'] == 'x' * (64 * 256)
        self.credentials_created.add((service, username))


@pytest.mark.skipif('sys.platform != "win32"')
def test_winvault_always_viable():
    """
    The WinVault backend should always be viable on Windows.
    """
    assert keyring.backends.Windows.WinVaultKeyring.viable


@pytest.mark.skipif('sys.platform != "win32"')
def test_winvaultattributes_always_viable():
    """
    The WinVault backend should always be viable on Windows.
    """
    assert keyring.backends.Windows.WinVaultAttributesKeyring.viable
