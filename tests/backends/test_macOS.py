import pytest

import keyring
from keyring.backends import macOS
from keyring.testing.util import random_string
from keyring.testing.backend import BackendBasicTests


@pytest.mark.skipif(
    not keyring.backends.macOS.Keyring.viable,
    reason="macOS backend not viable",
)
class Test_macOSKeychain(BackendBasicTests):
    def init_keyring(self):
        return macOS.Keyring()

    def test_list_generic_passwords(self):
        service = random_string(20)
        account = random_string(20)
        password = "non-blank"

        macOS.api.set_generic_password(None, service, account, password)

        items = macOS.api.list_generic_passwords()

        found = [
            item
            for item in items
            if item["service"] == service and item["account"] == account
        ]
        assert found, f"No item found for service={service} and account={account}"

        macOS.api.delete_generic_password(None, service, account)
