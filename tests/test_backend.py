"""Tests for keyring.backend.KeyringBackendMeta and KeyringBackend."""

from keyring import backend


class DummyKeyring(backend.KeyringBackend):
    priority = 1

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        self.saved = (service, username, password)


class TestSetPasswordKeyword:
    """
    KeyringBackendMeta._validate_username_in_set_password wraps every
    concrete backend's set_password() to validate the username. The wrapper
    must accept the same keyword arguments as the public API
    (``service``, matching KeyringBackend.set_password's own signature),
    not some other name. See #717.
    """

    def test_set_password_accepts_service_keyword(self):
        keyring = DummyKeyring()
        keyring.set_password(service="svc", username="user", password="pw")
        assert keyring.saved == ("svc", "user", "pw")

    def test_set_password_accepts_positional_args(self):
        keyring = DummyKeyring()
        keyring.set_password("svc", "user", "pw")
        assert keyring.saved == ("svc", "user", "pw")
