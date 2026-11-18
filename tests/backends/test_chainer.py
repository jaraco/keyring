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


class TestChainer:
    def test_chainer_gets_from_highest_priority(self, two_keyrings):
        chainer = keyring.backends.chainer.ChainerBackend()
        pw = chainer.get_password('alpha', 'bravo')
        assert pw == 'ring2-alpha-bravo'

    @pytest.fixture
    def keyrings_with_delete_password_error(self, monkeypatch):
        """
        Two keyrings where the higher-priority one raises
        PasswordDeleteError and the lower-priority one succeeds.
        """

        def get_two():
            class KeyringBase(backend.KeyringBackend):
                def get_password(self, system, user):
                    return None

                def set_password(self, system, user, password):
                    pass

            class Keyring1(KeyringBase):
                priority = 1

                def delete_password(self, system, user):
                    pass

            class Keyring2(KeyringBase):
                priority = 2

                def delete_password(self, system, user):
                    raise PasswordDeleteError("not found")

            return Keyring2(), Keyring1()

        monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)

    @pytest.fixture
    def keyrings_with_delete_not_implemented(self, monkeypatch):
        """
        Two keyrings where the higher-priority one raises
        NotImplementedError and the lower-priority one succeeds.
        """

        def get_two():
            class KeyringBase(backend.KeyringBackend):
                def get_password(self, system, user):
                    return None

                def set_password(self, system, user, password):
                    pass

            class Keyring1(KeyringBase):
                priority = 1

                def delete_password(self, system, user):
                    pass

            class Keyring2(KeyringBase):
                priority = 2

                def delete_password(self, system, user):
                    raise NotImplementedError()

            return Keyring2(), Keyring1()

        monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)

    def test_delete_password_falls_through_on_password_delete_error(
        self, keyrings_with_delete_password_error
    ):
        """
        The Chainer backend should try lower-priority backends when
        a higher-priority backend raises PasswordDeleteError.
        """
        chainer = keyring.backends.chainer.ChainerBackend()
        chainer.delete_password('system', 'username')
        # If no exception, test passes

    def test_delete_password_skips_not_implemented(
        self, keyrings_with_delete_not_implemented
    ):
        """
        The Chainer backend should skip backends that raise
        NotImplementedError and try the next one.
        """
        chainer = keyring.backends.chainer.ChainerBackend()
        chainer.delete_password('s', 'u')
        # If no exception, test passes

    def test_chainer_defers_to_fail(self, monkeypatch):
        monkeypatch.setattr('keyring.backend.get_all_keyring', tuple)
        assert keyring.backend.by_priority(
            keyring.backends.chainer.ChainerBackend
        ) < keyring.backend.by_priority(keyring.backends.fail.Keyring)
