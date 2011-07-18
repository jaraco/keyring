"""
Test case to access the keyring from the command line
"""

import os.path
import unittest

from keyring import cli
import keyring.backend


class FakeKeyring(keyring.backend.KeyringBackend):
    PASSWORD = "GABUZOMEUH"
    def supported(self):
        return 1

    def set_password(self, service, username, password):
        pass

    def get_password(self, service, username):
        return self.PASSWORD


class SimpleKeyring(keyring.backend.KeyringBackend):
    """A very simple keyring"""

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


class CommandLineTestCase(unittest.TestCase):
    def setUp(self):
        self.old_keyring = keyring.get_keyring()
        self.old_input_password = cli.input_password
        self.old_output_password = cli.output_password

        keyring.set_keyring(SimpleKeyring())
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
        self.assertEqual(1, cli.main([]))

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

    def test_load_builtin_backend(self):
        self.assertEqual(1, cli.main(["get",
                                      "-b", "keyring.backend.UncryptedFileKeyring",
                                      "foo", "bar"]))
        backend = keyring.get_keyring()
        self.assertTrue(isinstance(backend,
                                   keyring.backend.UncryptedFileKeyring))

    def test_load_specific_backend_with_path(self):
        keyring_path = os.path.join(os.path.dirname(keyring.__file__), 'tests')
        self.assertEqual(0, cli.main(["get",
                                      "-b", "test_cli.FakeKeyring",
                                      "-p", keyring_path,
                                      "foo", "bar"]))

        backend = keyring.get_keyring()
        # Somehow, this doesn't work, because the full dotted name of the class
        # is not the same as the one expected :(
        #self.assertTrue(isinstance(backend, FakeKeyring))
        self.assertEqual(FakeKeyring.PASSWORD, self.password_returned)

    def test_load_wrong_keyrings(self):
        self.assertRaises(SystemExit, cli.main,
                         ["get", "foo", "bar",
                          "-b", "blablabla" # ImportError
                         ])
        self.assertRaises(SystemExit, cli.main,
                         ["get", "foo", "bar",
                          "-b", "os.path.blabla" # AttributeError
                         ])
        self.assertRaises(SystemExit, cli.main,
                         ["get", "foo", "bar",
                          "-b", "__builtin__.str" # TypeError
                         ])



def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CommandLineTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
