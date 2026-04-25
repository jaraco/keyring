import sys
from unittest import mock

import pytest

import keyring.backends.Windows
from keyring.backends.Windows import _username_match
from keyring.testing.backend import UNICODE_CHARS, BackendBasicTests


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
        from ctypes import c_char, cast, create_string_buffer, sizeof

        from win32ctypes.core import _authentication as auth
        from win32ctypes.core.ctypes._common import LPBYTE

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


class TestUsernameMatch:
    """Tests for case-insensitive username comparison."""

    def test_same_case(self):
        assert _username_match('user', 'user')

    def test_different_case(self):
        assert _username_match('USER', 'user')
        assert _username_match('user', 'USER')
        assert _username_match('User', 'uSER')

    def test_not_matching(self):
        assert not _username_match('user1', 'user2')

    def test_none_values(self):
        assert _username_match(None, None)
        assert not _username_match('user', None)
        assert not _username_match(None, 'user')

    def test_empty_string(self):
        assert _username_match('', '')
        assert not _username_match('', 'user')


class TestWinVaultCaseInsensitive:
    """
    Test that WinVaultKeyring handles usernames case-insensitively.

    Uses mocking since win32cred is not available on non-Windows platforms.
    See https://github.com/jaraco/keyring/issues/736
    """

    def _make_credential(self, username, password):
        return keyring.backends.Windows.DecodingCredential({
            'UserName': username,
            'CredentialBlob': password.encode('utf-16'),
        })

    def _make_keyring(self):
        kr = keyring.backends.Windows.WinVaultKeyring.__new__(
            keyring.backends.Windows.WinVaultKeyring
        )
        return kr

    def test_get_password_different_case(self):
        """get_password should find a credential regardless of username case."""
        kr = self._make_keyring()
        cred = self._make_credential('USER', 'secret')

        with mock.patch.object(kr, '_read_credential', return_value=cred):
            result = kr.get_password('service', 'user')
        assert result == 'secret'

    def test_get_password_exact_case(self):
        """get_password should work with matching case."""
        kr = self._make_keyring()
        cred = self._make_credential('user', 'secret')

        with mock.patch.object(kr, '_read_credential', return_value=cred):
            result = kr.get_password('service', 'user')
        assert result == 'secret'

    def test_resolve_credential_case_insensitive(self):
        """_resolve_credential should match usernames case-insensitively."""
        kr = self._make_keyring()
        cred = self._make_credential('Admin', 'pass')

        with mock.patch.object(kr, '_read_credential', return_value=cred):
            result = kr._resolve_credential('service', 'admin')
        assert result is cred

    def test_resolve_credential_falls_through_on_mismatch(self):
        """_resolve_credential should try compound name for different users."""
        kr = self._make_keyring()
        cred_service = self._make_credential('user1', 'pass1')
        cred_compound = self._make_credential('user2', 'pass2')

        responses = {"service": cred_service, "user2@service": cred_compound}

        with mock.patch.object(kr, '_read_credential', side_effect=responses.get):
            result = kr._resolve_credential('service', 'user2')
        assert result is cred_compound

    def test_set_password_same_user_different_case(self):
        """
        set_password should not create compound entry when the same user
        (different case) updates their password.
        """
        kr = self._make_keyring()
        existing = self._make_credential('USER', 'old_pass')

        with (
            mock.patch.object(kr, '_read_credential', return_value=existing),
            mock.patch.object(kr, '_set_password') as mock_set,
        ):
            kr.set_password('service', 'user', 'new_pass')

        # Should only call _set_password once (update in place),
        # not twice (which would mean it moved to compound)
        mock_set.assert_called_once_with('service', 'user', 'new_pass')

    def test_set_password_different_user_creates_compound(self):
        """
        set_password should move existing credential to compound name
        when a different user sets a password for the same service.
        """
        kr = self._make_keyring()
        existing = self._make_credential('user1', 'pass1')

        with (
            mock.patch.object(kr, '_read_credential', return_value=existing),
            mock.patch.object(kr, '_set_password') as mock_set,
        ):
            kr.set_password('service', 'user2', 'pass2')

        assert mock_set.call_count == 2
        mock_set.assert_any_call('user1@service', 'user1', 'pass1')
        mock_set.assert_any_call('service', 'user2', 'pass2')

    def test_delete_password_case_insensitive(self):
        """delete_password should match usernames case-insensitively."""
        kr = self._make_keyring()
        cred = self._make_credential('USER', 'secret')

        def fake_read(target):
            if target == 'service':
                return cred
            return None

        with (
            mock.patch.object(kr, '_read_credential', side_effect=fake_read),
            mock.patch.object(kr, '_delete_password') as mock_del,
        ):
            kr.delete_password('service', 'user')

        mock_del.assert_called_once_with('service')

    def test_get_credential_case_insensitive(self):
        """get_credential should find credentials case-insensitively."""
        kr = self._make_keyring()
        cred = self._make_credential('Admin', 'secret')

        with mock.patch.object(kr, '_read_credential', return_value=cred):
            result = kr.get_credential('service', 'admin')

        assert result is not None
        assert result.username == 'Admin'
        assert result.password == 'secret'
