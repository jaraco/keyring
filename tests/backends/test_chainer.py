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

            def delete_password(self, system, user):
                pass

        class Keyring2(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return f'ring2-{system}-{user}'

            def set_password(self, system, user, password):
                raise NotImplementedError()

            def delete_password(self, system, user):
                raise PasswordDeleteError("Password not found")

        return Keyring1(), Keyring2()

    monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)


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

    def test_chainer_delete_skips_missing(self, two_keyrings):
        """
        When a higher-priority backend raises PasswordDeleteError,
        the chainer should fall through to the next backend.
        """
        chainer = keyring.backends.chainer.ChainerBackend()
        # Should not raise even though Keyring2 (higher priority)
        # raises PasswordDeleteError
        chainer.delete_password('alpha', 'bravo')
