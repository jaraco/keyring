import pytest

import keyring.backends.chainer
from keyring import backend
from keyring.errors import PasswordDeleteError


@pytest.fixture
def two_keyrings(monkeypatch):
    def get_two():
        class Keyring1(backend.KeyringBackend):
            priority = 1

            def get_password(self, system, user):
                return f'ring1-{system}-{user}'

            def set_password(self, system, user, password):
                pass

        class Keyring2(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return f'ring2-{system}-{user}'

            def set_password(self, system, user, password):
                raise NotImplementedError()

        return Keyring1(), Keyring2()

    monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)


@pytest.fixture
def delete_test_keyrings(monkeypatch):
    """
    Fixture that creates backends where passwords exist in lower priority backend.
    """

    class HighPriorityKeyring(backend.KeyringBackend):
        priority = 2

        def get_password(self, system, user):
            return None

        def set_password(self, system, user, password):
            pass

        def delete_password(self, system, user):
            raise PasswordDeleteError("Password not found")

    class LowPriorityKeyring(backend.KeyringBackend):
        priority = 1
        storage = {}

        def __init__(self):
            self.storage = {('test', 'user'): 'old-password'}

        def get_password(self, system, user):
            return self.storage.get((system, user))

        def set_password(self, system, user, password):
            pass

        def delete_password(self, system, user):
            key = (system, user)
            if key in self.storage:
                del self.storage[key]
            else:
                raise PasswordDeleteError("Password not found")

    high = HighPriorityKeyring()
    low = LowPriorityKeyring()

    monkeypatch.setattr('keyring.backend.get_all_keyring', lambda: [high, low])
    return high, low


class TestChainer:
    def test_chainer_gets_from_highest_priority(self, two_keyrings):
        chainer = keyring.backends.chainer.ChainerBackend()
        pw = chainer.get_password('alpha', 'bravo')
        assert pw == 'ring2-alpha-bravo'

    def test_chainer_defers_to_fail(self, monkeypatch):
        """
        The Chainer backend should defer to the Fail backend when there are
        no backends to be chained.
        """
        monkeypatch.setattr('keyring.backend.get_all_keyring', tuple)
        assert keyring.backend.by_priority(
            keyring.backends.chainer.ChainerBackend
        ) < keyring.backend.by_priority(keyring.backends.fail.Keyring)

    def test_delete_password_tries_all_backends(self, delete_test_keyrings):
        """
        Test that delete_password tries all backends in the chain,
        not just the highest priority one. Addresses issue #697.
        """
        high, low = delete_test_keyrings
        chainer = keyring.backends.chainer.ChainerBackend()

        # Verify set_password is defined (required by ABC) but is a no-op
        high.set_password('test', 'user', 'ignored')
        low.set_password('test', 'extra', 'ignored')

        # Verify the password exists in the low priority backend
        assert low.get_password('test', 'user') == 'old-password'
        # Verify it doesn't exist in high priority backend
        assert high.get_password('test', 'user') is None
        # Verify chainer can retrieve it
        assert chainer.get_password('test', 'user') == 'old-password'

        # Now delete it via chainer - should succeed even though high priority backend fails
        chainer.delete_password('test', 'user')

        # Verify it's deleted from low priority backend
        assert low.get_password('test', 'user') is None
        # Verify chainer can't retrieve it anymore
        assert chainer.get_password('test', 'user') is None

    def test_delete_password_raises_if_all_backends_fail(self, delete_test_keyrings):
        """
        Test that delete_password raises PasswordDeleteError if all backends fail.
        """
        high, low = delete_test_keyrings
        chainer = keyring.backends.chainer.ChainerBackend()

        # Try to delete a password that doesn't exist anywhere
        with pytest.raises(PasswordDeleteError):
            chainer.delete_password('nonexistent', 'user')
