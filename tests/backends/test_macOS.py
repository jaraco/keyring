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


class _FakeAPIError(Exception):
    pass


class _FakeKeychainDenied(_FakeAPIError):
    pass


class _FakeNotFound(_FakeAPIError):
    pass


def test_delete_password_keychain_denied_raises_locked(monkeypatch):
    """Denied keychain prompt on delete must match get/set → KeyringLocked (#772)."""
    import types

    from keyring.backends import macOS
    from keyring.errors import KeyringLocked, PasswordDeleteError

    def deny(*_args, **_kwargs):
        raise _FakeKeychainDenied(-128, "Keychain Access Denied")

    fake_api = types.SimpleNamespace(
        Error=_FakeAPIError,
        KeychainDenied=_FakeKeychainDenied,
        NotFound=_FakeNotFound,
        delete_generic_password=deny,
    )
    monkeypatch.setattr(macOS, "api", fake_api, raising=False)

    keyring_backend = object.__new__(macOS.Keyring)
    keyring_backend.keychain = None

    with pytest.raises(KeyringLocked, match="Can't delete password in keychain"):
        keyring_backend.delete_password("service", "user")


def test_delete_password_other_error_still_password_delete(monkeypatch):
    import types

    from keyring.backends import macOS
    from keyring.errors import PasswordDeleteError

    def fail(*_args, **_kwargs):
        raise _FakeAPIError(-1, "other")

    fake_api = types.SimpleNamespace(
        Error=_FakeAPIError,
        KeychainDenied=_FakeKeychainDenied,
        NotFound=_FakeNotFound,
        delete_generic_password=fail,
    )
    monkeypatch.setattr(macOS, "api", fake_api, raising=False)

    keyring_backend = object.__new__(macOS.Keyring)
    keyring_backend.keychain = None

    with pytest.raises(PasswordDeleteError, match="Can't delete password in keychain"):
        keyring_backend.delete_password("service", "user")
