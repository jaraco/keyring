"""
test_backend.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""


import commands
import contextlib
import os
import random
import string
import sys
import types
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

def backup(file):
    """Backup the file as file.bak
    """
    commands.getoutput( "mv %s{,.bak}" % file )

def restore(file):
    """Restore the file from file.bak
    """
    commands.getoutput( "mv %s{.bak,}" % file )

class BackendBasicTestCase(unittest.TestCase):
    """Test for the keyring's basic funtions. password_set and password_get
    """

    __test__ = False

    def setUp(self):
        self.keyring = self.init_keyring()

    def check_set_get(self, service, username, password):
        keyring = self.keyring

        if self.supported() == -1: # skip the unsupported keyring
            return

        # for the non-exsit password
        self.assertEqual(keyring.get_password(service, username), None)

        # common usage
        keyring.set_password(service, username, password)
        self.assertEqual(keyring.get_password(service, username), password)

        # for the empty password
        keyring.set_password(service, username, "")
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

    def supported(self):
        """Return the correct value for supported.
        """
        return -1

    def test_supported(self):
        """Test the keyring's supported value.
        """
        self.assertEqual(self.keyring.supported(), self.supported())

class OSXKeychainTestCase(BackendBasicTestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, "Testing OSXKeychain, following password prompts are for this keyring"
        return keyring.backend.OSXKeychain()

    def supported(self):
        if sys.platform in ('mac','darwin'):
            return 1
        return -1

class GnomeKeyringTestCase(BackendBasicTestCase):
    __test__ = True

    def environ(self):
        return dict(GNOME_KEYRING_CONTROL='1',
                    DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        print >> sys.stderr, "Testing GnomeKeyring, following password prompts are for this keyring"
        return keyring.backend.GnomeKeyring()

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


class KDEKWalletTestCase(BackendBasicTestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, "Testing KDEKWallet, following password prompts are for this keyring"
        return keyring.backend.KDEKWallet()

    def supported(self):
        return self.keyring.supported()


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


class KDEKWalletInQApplication(unittest.TestCase):


    def test_QApplication(self):
        try:
            from PyKDE4.kdeui import KWallet
            from PyQt4.QtGui import QApplication
        except:
            return
                    
        app = QApplication([])
        wallet=keyring.backend.open_kwallet()
        self.assertTrue(isinstance(wallet,KWallet.Wallet),msg="The object wallet should be type<KWallet.Wallet> but it is: %s"%repr(wallet))
        app.exit()


class FileKeyringTestCase(BackendBasicTestCase):
    __test__ = False

    def setUp(self):
        """Backup the file before the test
        """
        self.keyring = self.init_keyring()

        self.file_path = os.path.join(os.path.expanduser("~"),
                                                       self.keyring.filename())
        backup(self.file_path)

    def tearDown(self):
        """Restore the keyring file.
        """
        restore(self.file_path)

    def test_encrypt_decrypt(self):
        if self.supported() == -1: # skip the unsupported platform
            return

        password = random_string(20)
        encyrpted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encyrpted))

class UncryptedFileKeyringTestCase(FileKeyringTestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, "Testing UnecryptedFile, following password prompts are for this keyring"
        return keyring.backend.UncryptedFileKeyring()

    def supported(self):
        return 0

class CryptedFileKeyringTestCase(FileKeyringTestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, "Testing CryptedFile, following password prompts are for this keyring"
        return keyring.backend.CryptedFileKeyring()

    def supported(self):
        try:
            from Crypto.Cipher import AES
            return 0
        except ImportError:
            pass
        return -1

class Win32CryptoKeyringTestCase(FileKeyringTestCase):
    __test__ = True

    def init_keyring(self):
        print >> sys.stderr, "Testing Win32, following password prompts are for this keyring"
        return keyring.backend.Win32CryptoKeyring()

    def supported(self):
        try:
            import win32_crypto
            if sys.platform in ['win32'] and sys.getwindowsversion()[-2] == 2:
                return 1
        except ImportError:
            pass
        return -1

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
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
