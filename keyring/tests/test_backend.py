"""
test_backend.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""

import contextlib
import os
import random
import string
import sys
import tempfile
import types

try:
    # Python < 2.7 annd Python >= 3.0 < 3.1
    import unittest2 as unittest
except ImportError:
    import unittest

import keyring.backend
from keyring.backend import PasswordSetError

ALPHABET = string.ascii_letters + string.digits
DIFFICULT_CHARS = string.whitespace + string.punctuation

class ImportKiller(object):
    "Context manager to make an import of a given name or names fail."
    def __init__(self, *names):
        self.names = names
    def find_module(self, fullname, path=None):
        if fullname in self.names:
            return self
    def load_module(self, fullname):
        assert fullname in self.names
        raise ImportError(fullname)
    def __enter__(self):
        self.original = {}
        for name in self.names:
            self.original[name] = sys.modules.pop(name, None)
        sys.meta_path.append(self)
    def __exit__(self, *args):
        sys.meta_path.remove(self)
        for key, value in self.original.items():
            if value is not None:
                sys.modules[key] = value


@contextlib.contextmanager
def NoNoneDictMutator(destination, **changes):
    """Helper context manager to make and unmake changes to a dict.

    A None is not a valid value for the destination, and so means that the
    associated name should be removed."""
    original = {}
    for key, value in changes.items():
        original[key] = destination.get(key)
        if value is None:
            if key in destination:
                del destination[key]
        else:
            destination[key] = value
    yield
    for key, value in original.items():
        if value is None:
            if key in destination:
                del destination[key]
        else:
            destination[key] = value


def Environ(**changes):
    """A context manager to temporarily change the os.environ"""
    return NoNoneDictMutator(os.environ, **changes)


def ImportBlesser(*names, **changes):
    """A context manager to temporarily make it possible to import a module"""
    for name in names:
        changes[name] = types.ModuleType(name)
    return NoNoneDictMutator(sys.modules, **changes)


def random_string(k, source = ALPHABET):
    """Generate a random string with length <i>k</i>
    """
    result = ''
    for i in range(0, k):
        result += random.choice(source)
    return result


def is_win32_crypto_supported():
    try:
        from keyring.backends import win32_crypto
        if sys.platform in ['win32'] and sys.getwindowsversion()[-2] == 2:
            return True
    except ImportError:
        pass
    return False

def is_osx_keychain_supported():
    return sys.platform in ('mac','darwin')

def is_kwallet_supported():
    supported = keyring.backend.KDEKWallet().supported()
    if supported == -1:
        return False
    return True

def is_crypto_supported():
    try:
        from Crypto.Cipher import AES
        import crypt
    except ImportError:
        return False
    return True

def is_gnomekeyring_supported():
    supported = keyring.backend.GnomeKeyring().supported()
    if supported == -1:
        return False
    return True

def is_qt4_supported():
    try:
        from PyQt4.QtGui import QApplication
    except ImportError:
        return False
    return True

def is_winvault_supported():
    try:
        from keyring.backend import WinVaultKeyring
        if sys.platform in ['win32'] and sys.getwindowsversion().major >= 6:
            return True
    except ImportError:
        pass
    return False


class BackendBasicTests(object):
    """Test for the keyring's basic funtions. password_set and password_get
    """

    def setUp(self):
        self.keyring = self.init_keyring()
        self.credentials_created = set()

    def set_password(self, service, username, password):
        # set the password and save the result so the test runner can clean
        #  up after if necessary.
        self.keyring.set_password(service, username, password)
        self.credentials_created.add((service, username))

    def check_set_get(self, service, username, password):
        keyring = self.keyring

        # for the non-existent password
        self.assertEqual(keyring.get_password(service, username), None)

        # common usage
        self.set_password(service, username, password)
        self.assertEqual(keyring.get_password(service, username), password)

        # for the empty password
        self.set_password(service, username, "")
        self.assertEqual(keyring.get_password(service, username), "")

    def test_password_set_get(self):
        password = random_string(20)
        username = random_string(20)
        service = random_string(20)
        self.check_set_get(service, username, password)

    def test_difficult_chars(self):
        password = random_string(20, DIFFICULT_CHARS)
        username = random_string(20, DIFFICULT_CHARS)
        service = random_string(20, DIFFICULT_CHARS)
        self.check_set_get(service, username, password)

    def test_different_user(self):
        """
        Issue #47 reports that WinVault isn't storing passwords for
        multiple users. This test exercises that test for each of the
        backends.
        """

        keyring = self.keyring
        self.set_password('service1', 'user1', 'password1')
        self.set_password('service1', 'user2', 'password2')
        self.assertEqual(keyring.get_password('service1', 'user1'),
            'password1')
        self.assertEqual(keyring.get_password('service1', 'user2'),
            'password2')
        self.set_password('service2', 'user3', 'password3')
        self.assertEqual(keyring.get_password('service1', 'user1'),
            'password1')

@unittest.skipUnless(is_osx_keychain_supported(),
                     "Need OS X")
class OSXKeychainTestCase(BackendBasicTests, unittest.TestCase):

    def init_keyring(self):
        return keyring.backend.OSXKeychain()


@unittest.skipUnless(is_gnomekeyring_supported(),
                     "Need GnomeKeyring")
class GnomeKeyringTestCase(BackendBasicTests, unittest.TestCase):

    def environ(self):
        return dict(GNOME_KEYRING_CONTROL='1',
                    DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        k = keyring.backend.GnomeKeyring()

        # Store passwords in the session (in-memory) keyring for the tests. This
        # is going to be automatically cleared when the user logoff.
        k.KEYRING_NAME = 'session'

        return k

    def test_supported(self):
        with ImportBlesser('gnomekeyring'):
            with Environ(**self.environ()):
                self.assertEqual(1, self.keyring.supported())

    def test_supported_no_module(self):
        with ImportKiller('gnomekeyring'):
            with Environ(**self.environ()):
                self.assertEqual(-1, self.keyring.supported())

    def test_supported_no_keyring(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['GNOME_KEYRING_CONTROL'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())

    def test_supported_no_display(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['DISPLAY'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())

    def test_supported_no_session(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['DBUS_SESSION_BUS_ADDRESS'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())


@unittest.skipUnless(is_kwallet_supported(),
                     "Need KWallet")
class KDEKWalletTestCase(BackendBasicTests, unittest.TestCase):

    def init_keyring(self):
        return keyring.backend.KDEKWallet()


class UnOpenableKWallet(object):
    """A module-like object used to test KDE wallet fall-back."""

    Synchronous = None

    def openWallet(self, *args):
        return None

    def NetworkWallet(self):
        return None


class FauxQtGui(object):
    """A fake module-like object used in testing the open_kwallet function."""

    class qApp:
        @staticmethod
        def instance():
            pass

    class QApplication(object):
        def __init__(self, *args):
            pass

        def exit(self):
            pass

    class QWidget(object):
        def __init__(self, *args):
            pass

        def winId(self):
            pass

class KDEWalletCanceledTestCase(unittest.TestCase):

    def test_user_canceled(self):
        # If the user cancels either the "enter your password to unlock the
        # keyring" dialog or clicks "deny" on the "can this application access
        # the wallet" dialog then openWallet() will return None.  The
        # open_wallet() function should handle that eventuality by returning
        # None to signify that the KWallet backend is not available.
        self.assertEqual(
            keyring.backend.open_kwallet(UnOpenableKWallet(), FauxQtGui()),
            None)


@unittest.skipUnless(is_kwallet_supported() and
                     is_qt4_supported(),
                     "Need KWallet and Qt4")
class KDEKWalletInQApplication(unittest.TestCase):
    def test_QApplication(self):
        try:
            from PyKDE4.kdeui import KWallet
            from PyQt4.QtGui import QApplication
        except:
            return

        app = QApplication([])
        wallet = keyring.backend.open_kwallet()
        self.assertTrue(isinstance(wallet, KWallet.Wallet),
                        msg="The object wallet should be type "
                        "<KWallet.Wallet> but it is: %s" % repr(wallet))
        app.exit()


class FileKeyringTests(BackendBasicTests):

    def setUp(self):
        super(FileKeyringTests, self).setUp()
        self.keyring = self.init_keyring()
        self.keyring.file_path = self.tmp_keyring_file = tempfile.mktemp()

    def tearDown(self):
        try:
            os.unlink(self.tmp_keyring_file)
        except OSError, e:
            if e.errno != 2: # No such file or directory
                raise

    def test_encrypt_decrypt(self):
        password = random_string(20)
        # keyring.encrypt expects bytes
        password = password.encode('utf-8')
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))


class UncryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):


    def init_keyring(self):
        return keyring.backend.UncryptedFileKeyring()


@unittest.skipUnless(is_crypto_supported(),
                     "Need Crypto module")
class CryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.keyring._getpass = lambda *args, **kwargs: "abcdef"

    def init_keyring(self):
        return keyring.backend.CryptedFileKeyring()


@unittest.skipUnless(is_win32_crypto_supported(),
                     "Need Windows")
class Win32CryptoKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def init_keyring(self):
        return keyring.backend.Win32CryptoKeyring()


@unittest.skipUnless(is_winvault_supported(),
                     "Need WinVault")
class WinVaultKeyringTestCase(BackendBasicTests, unittest.TestCase):
    def tearDown(self):
        # clean up any credentials created
        for cred in self.credentials_created:
            try:
                self.keyring.delete_password(*cred)
            except Exception, e:
                print >> sys.stderr, e

    def init_keyring(self):
        return keyring.backend.WinVaultKeyring()

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(OSXKeychainTestCase))
    suite.addTest(unittest.makeSuite(GnomeKeyringTestCase))
    suite.addTest(unittest.makeSuite(KDEWalletCanceledTestCase))
    suite.addTest(unittest.makeSuite(KDEKWalletTestCase))
    suite.addTest(unittest.makeSuite(KDEKWalletInQApplication))
    suite.addTest(unittest.makeSuite(UncryptedFileKeyringTestCase))
    suite.addTest(unittest.makeSuite(CryptedFileKeyringTestCase))
    suite.addTest(unittest.makeSuite(Win32CryptoKeyringTestCase))
    suite.addTest(unittest.makeSuite(WinVaultKeyringTestCase))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
