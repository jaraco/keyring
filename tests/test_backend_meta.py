"""Tests for keyring.backend.KeyringBackendMeta."""

import warnings

import pytest

from keyring import backend


class BaseKeyring(backend.KeyringBackend):
    """A backend defining ``set_password``, so the metaclass wraps it once."""

    priority = 1

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        self.saved = (service, username, password)


class DerivedKeyring(BaseKeyring):
    """A subclass inheriting ``set_password``, so it must not be re-wrapped."""


class TestValidateUsernameInSetPassword:
    def test_validates_username_once(self):
        """
        The metaclass wraps ``set_password`` on every class it creates, but a
        subclass that merely inherits ``set_password`` already has the
        wrapped version. Re-wrapping makes the username validation (and its
        deprecation warning) run once per class in the MRO.
        """
        keyring = DerivedKeyring()
        with pytest.deprecated_call() as record:
            keyring.set_password('svc', '', 'pw')
        assert len(record) == 1
        assert keyring.saved == ('svc', '', 'pw')

    def test_overridden_set_password_is_still_wrapped(self):
        """
        A subclass that supplies its own ``set_password`` is not yet
        wrapped, so it must be.
        """

        class OverridingKeyring(BaseKeyring):
            def set_password(self, service, username, password):
                self.saved = (service, username, password)

        keyring = OverridingKeyring()
        with pytest.deprecated_call() as record:
            keyring.set_password('svc', '', 'pw')
        assert len(record) == 1
        assert keyring.saved == ('svc', '', 'pw')

    def test_no_warning_for_nonempty_username(self):
        keyring = DerivedKeyring()
        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter('always')
            keyring.set_password('svc', 'user', 'pw')
        assert [w for w in record if w.category is DeprecationWarning] == []
