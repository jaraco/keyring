import pytest

import keyring.backends.chainer
from keyring import backend, errors


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
def password_in_lower_priority_only(monkeypatch):
    """
    Two backends where only the lower-priority one actually has the
    password stored -- e.g. because the higher-priority backend was
    only installed/configured after the password was originally set,
    matching the scenario in GH #697.
    """
    deleted = []

    def get_two():
        class HigherPriorityWithoutPassword(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return None

            def set_password(self, system, user, password):
                pass

            def delete_password(self, system, user):
                raise errors.PasswordDeleteError('Password not found')

        class LowerPriorityWithPassword(backend.KeyringBackend):
            priority = 1

            def get_password(self, system, user):
                return f'stored-{system}-{user}'

            def set_password(self, system, user, password):
                pass

            def delete_password(self, system, user):
                deleted.append((system, user))

        return HigherPriorityWithoutPassword(), LowerPriorityWithPassword()

    monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)
    return deleted


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

    def test_chainer_deletes_from_lower_priority_backend(
        self, password_in_lower_priority_only
    ):
        """
        Regression test for
        https://github.com/jaraco/keyring/issues/697

        delete_password() must fall through to a lower-priority
        backend when a higher-priority backend supports deletion but
        doesn't have this particular password (raises
        PasswordDeleteError), the same way get_password() already
        tries every backend rather than stopping at the first one
        that doesn't have it.
        """
        deleted = password_in_lower_priority_only
        chainer = keyring.backends.chainer.ChainerBackend()
        # Sanity check this fixture matches the reported scenario:
        # get_password() already correctly finds it in the lower-
        # priority backend.
        assert chainer.get_password('alpha', 'bravo') == 'stored-alpha-bravo'

        # Must not raise, and must actually reach the backend that
        # has the password.
        chainer.delete_password('alpha', 'bravo')

        assert ('alpha', 'bravo') in deleted

