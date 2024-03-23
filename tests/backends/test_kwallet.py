import pytest

from keyring.backends import kwallet
from keyring.testing.backend import BackendBasicTests


@pytest.mark.skipif(not kwallet.DBusKeyring.viable, reason="KWallet5 unavailable")
class TestDBusKWallet(BackendBasicTests):
    # Remove '@' from service name as this is not supported in service names
    # '@' will cause troubles during migration of kwallet entries
    DIFFICULT_CHARS = BackendBasicTests.DIFFICULT_CHARS.replace('@', '')

    def init_keyring(self):
        return kwallet.DBusKeyring()

    def cleanup(self):
        for item in self.credentials_created:
            # Suppress errors, as only one pre/post migration item will be
            # present
            try:
                self.keyring.delete_password(*item)
            except BaseException:
                pass

        # TODO Remove empty folders created during tests

    def set_password(self, service, username, password, old_format=False):
        # set the password and save the result so the test runner can clean
        #  up after if necessary.
        self.credentials_created.add((service, username))

        if old_format:
            username = username + '@' + service
            service = 'Python'

        super().set_password(service, username, password)

    def check_set_get(self, service, username, password):
        keyring = self.keyring

        # for the non-existent password
        assert keyring.get_password(service, username) is None

        # common usage
        self.set_password(service, username, password, True)
        # re-init keyring to force migration
        self.keyring = keyring = self.init_keyring()
        ret_password = keyring.get_password(service, username)
        assert ret_password == password, (
            f"Incorrect password for username: '{service}' "
            f"on service: '{username}'. '{ret_password}' != '{password}'",
        )

        # for the empty password
        self.set_password(service, username, "", True)
        # re-init keyring to force migration
        self.keyring = keyring = self.init_keyring()
        ret_password = keyring.get_password(service, username)
        assert ret_password == ""
        ret_password = keyring.get_password('Python', username + '@' + service)
        assert ret_password is None


@pytest.mark.skipif(
    not kwallet.DBusKeyringKWallet4.viable, reason="KWallet4 unavailable"
)
class TestDBusKWallet4(TestDBusKWallet):
    def init_keyring(self):
        return kwallet.DBusKeyringKWallet4()
