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

    def set_utf8_password(self, service, username, password):
        """
        Write a UTF-8 encoded password using win32ctypes primitives
        """
        from win32ctypes.core import _authentication as auth
        from win32ctypes.core.ctypes._common import LPBYTE
        from ctypes import cast, c_char, create_string_buffer, sizeof

        credential = dict(
            Type=1,
            TargetName=service,
            UserName=username,
            CredentialBlob=password,
            Comment="Stored using python-keyring",
            Persist=3,
        )

        c_cred = auth.CREDENTIAL.fromdict(credential, 0)
        blob_data = create_string_buffer(password.encode("utf-8"))
        c_cred.CredentialBlobSize = sizeof(blob_data) - sizeof(c_char)
        c_cred.CredentialBlob = cast(blob_data, LPBYTE)
        c_cred_pointer = auth.PCREDENTIAL(c_cred)
        auth._CredWrite(c_cred_pointer, 0)

        self.credentials_created.add((service, username))

    def test_long_password_nice_error(self):
        self.keyring.set_password('system', 'user', 'x' * 512 * 2)

    def test_read_utf8_password(self):
        """
        Write a UTF-8 encoded credential and make sure it can be read back correctly.
        """
        service = "keyring-utf8-test"
        username = "keyring"
        password = "utf8-test" + UNICODE_CHARS

        self.set_utf8_password(service, username, password)
        assert self.keyring.get_password(service, username) == password


@pytest.mark.skipif('sys.platform != "win32"')
def test_winvault_always_viable():
    """
    The WinVault backend should always be viable on Windows.
    """
    assert keyring.backends.Windows.WinVaultKeyring.viable


@pytest.mark.skipif('sys.platform != "win32"')
def test_long_password():
    keyring_backend = keyring.backends.Windows.WinVaultKeyring()

    max_password = keyring_backend._max_password

    passwords = dict(
        short_password='password',
        almost_too_long_password='a' * max_password,
        too_long_password='a' * (max_password + 1),
        way_too_long_password='a' * 2**20
    )

    results = dict(
        short_password=False,
        almost_too_long_password=False,
        too_long_password=False,
        way_too_long_password=False
    )

    for test_case, password in passwords.items():
        try:
            keyring.set_password('__system__', test_case, password)
            pwd = keyring.get_password('__system__', test_case)
            print(pwd)
            keyring.delete_password('__system__', test_case)
            results[test_case] = True
        except Exception as e:
            if isinstance(e, ValueError):
                results[test_case] = True
            elif e.winerror != 1783 or e.funcname != 'CredWrite' or test_case != 'too_long_password':
                results[test_case] = False
            else:
                results[test_case] = True

    assert all(result for result in results.values())
