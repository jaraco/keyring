import pytest

from keyring.backends import libsecret
from keyring.testing.backend import BackendBasicTests
from keyring.testing.util import NoNoneDictMutator


@pytest.mark.skipif(
    not libsecret.Keyring.viable,
    reason="libsecret package is needed for LibSecretKeyring",
)
class TestLibSecretKeyring(BackendBasicTests):
    __test__ = True

    def init_keyring(self):
        print(
            "Testing LibSecretKeyring; the following "
            "password prompts are for this keyring"
        )
        keyring = libsecret.Keyring()
        keyring.collection = 'session'
        return keyring


class TestUnits:
    def test_supported_no_libsecret(self):
        """
        LibSecretKeyring is not viable if Secret can't be imported.
        """
        with NoNoneDictMutator(libsecret.__dict__, Secret=None):
            assert not libsecret.Keyring.viable
