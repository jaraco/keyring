import pytest

from keyring.backends import SecretService
from keyring.testing.backend import BackendBasicTests
from keyring.testing.util import NoNoneDictMutator


@pytest.mark.skipif(
    not SecretService.Keyring.viable,
    reason="SecretStorage package is needed for SecretServiceKeyring",
)
class TestSecretServiceKeyring(BackendBasicTests):
    __test__ = True

    def init_keyring(self):
        print(
            "Testing SecretServiceKeyring; the following "
            "password prompts are for this keyring"
        )
        keyring = SecretService.Keyring()
        keyring.preferred_collection = '/org/freedesktop/secrets/collection/session'
        return keyring


class TestUnits:
    def test_supported_no_secretstorage(self):
        """
        SecretService Keyring is not viable if secretstorage can't be imported.
        """
        with NoNoneDictMutator(SecretService.__dict__, secretstorage=None):
            assert not SecretService.Keyring.viable
