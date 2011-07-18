"""
Test case to access the keyring from the command line
"""

import getpass
import unittest

from keyring import cli
import keyring.backend


class CommandLineTestCase(unittest.TestCase):
    def setUp(self):
        class FakeKeyring(keyring.backend.KeyringBackend):
            def __init__(self):
                self.pwd = {}

            def supported(self):
                return 1

            def set_password(self, service, username, password):
                self.pwd[(service, username)] = password

            def get_password(self, service, username):
                try:
                    return self.pwd[(service, username)]
                except KeyError:
                    return None

        self.old_keyring = keyring.get_keyring()
        self.old_input_password = cli.input_password
        self.old_output_password = cli.output_password

        keyring.set_keyring(FakeKeyring())
        self.password = ""
        self.password_returned = None
        cli.input_password = self.return_password
        cli.output_password = self.save_password

    def tearDown(self):
        keyring.set_keyring(self.old_keyring)
        cli.input_password = self.old_input_password
        cli.output_password = self.old_output_password

    def return_password(self, *args, **kwargs):
        return self.password

    def save_password(self, password):
        self.password_returned = password


    def test_wrong_arguments(self):
        self.assertRaises(SystemExit, cli.main, [])

        self.assertRaises(SystemExit, cli.main, ["get"])
        self.assertRaises(SystemExit, cli.main, ["get", "foo"])
        self.assertRaises(SystemExit, cli.main, ["get", "foo", "bar", "baz"])

        self.assertRaises(SystemExit, cli.main, ["set"])
        self.assertRaises(SystemExit, cli.main, ["set", "foo"])
        self.assertRaises(SystemExit, cli.main, ["set", "foo", "bar", "baz"])

        self.assertRaises(SystemExit, cli.main, ["foo", "bar", "baz"])

    def test_get_unexistent_password(self):
        self.assertEqual(1, cli.main(["get", "foo", "bar"]))
        self.assertEqual(None, self.password_returned)

    def test_set_and_get_password(self):
        self.password = "plop"
        self.assertEqual(0, cli.main(["set", "foo", "bar"]))
        self.assertEqual(0, cli.main(["get", "foo", "bar"]))
        self.assertEqual("plop", self.password_returned)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CommandLineTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
