import pytest

import keyring.backends.chainer
from keyring import backend


@pytest.fixture
def two_keyrings(monkeypatch):
    def get_two():
        class Keyring1(backend.KeyringBackend):
            priority = 1

            def get_password(self, system, user):
                return 'ring1-{system}-{user}'.format(**locals())

            def set_password(self, system, user, password):
                pass

        class Keyring2(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return 'ring2-{system}-{user}'.format(**locals())

            def set_password(self, system, user, password):
                raise NotImplementedError()

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
