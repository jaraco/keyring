import unittest

from keyring.backends import kwallet
from ..test_backend import BackendBasicTests


@unittest.skipUnless(kwallet.DBusKeyring.viable, "KWallet5 unavailable")
class DBusKWalletTestCase(BackendBasicTests, unittest.TestCase):

    # Remove '@' from service name as this is not supported in service names
    # '@' will cause troubles during migration of kwallet entries
    DIFFICULT_CHARS = BackendBasicTests.DIFFICULT_CHARS.replace('@', '')

    def init_keyring(self):
        return kwallet.DBusKeyring()

    def tearDown(self):
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

        super().set_password(
            service,
            username,
            password)

    def check_set_get(self, service, username, password):
        keyring = self.keyring

        # for the non-existent password
        self.assertEqual(keyring.get_password(service, username), None)

        # common usage
        self.set_password(service, username, password, True)
        # re-init keyring to force migration
        self.keyring = keyring = self.init_keyring()
        ret_password = keyring.get_password(service, username)
        self.assertEqual(
            ret_password, password,
            "Incorrect password for username: '%s' "
            "on service: '%s'. '%s' != '%s'"
            % (service, username, ret_password, password))

        # for the empty password
        self.set_password(service, username, "", True)
        # re-init keyring to force migration
        self.keyring = keyring = self.init_keyring()
        ret_password = keyring.get_password(service, username)
        self.assertEqual(
            ret_password, "",
            "Incorrect password for username: '%s' "
            "on service: '%s'. '%s' != '%s'"
            % (service, username, ret_password, ""))
        ret_password = keyring.get_password('Python', username + '@' + service)
        self.assertEqual(
            ret_password, None,
            "Not 'None' password returned for username: '%s' "
            "on service: '%s'. '%s' != '%s'. Passwords from old "
            "folder should be deleted during migration."
            % (service, username, ret_password, None))


@unittest.skipUnless(kwallet.DBusKeyringKWallet4.viable,
                     "KWallet4 unavailable")
class DBusKWallet4TestCase(DBusKWalletTestCase):
    def init_keyring(self):
        return kwallet.DBusKeyringKWallet4()
