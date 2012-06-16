"""
test_backend.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""

import base64
import codecs
import cPickle
import contextlib
import getpass
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

from keyring.tests import mocks

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
        __import__('keyring.backends.win32_crypto')
    except ImportError:
        return False
    return sys.platform in ['win32'] and sys.getwindowsversion()[-2] == 2

def is_osx_keychain_supported():
    return sys.platform in ('mac','darwin')

def is_kwallet_supported():
    supported = keyring.backend.KDEKWallet().supported()
    if supported == -1:
        return False
    return True

def is_crypto_supported():
    try:
        __import__('Crypto.Cipher.AES')
        __import__('Crypto.Protocol.KDF')
        __import__('Crypto.Random')
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
        __import__('PyQt4.QtGui')
    except ImportError:
        return False
    return True

def is_winvault_supported():
    try:
        __import__('win32cred')
        has_pywin32 = True
    except ImportError:
        has_pywin32 = False
    return (
        sys.platform in ['win32'] and sys.getwindowsversion().major >= 6
        and has_pywin32
    )

def is_dbus_supported():
    try:
        __import__('dbus')
    except ImportError:
        return False
    return True

def is_keyczar_supported():
    try:
        __import__('keyczar')
    except ImportError:
        print 'NO KEYCZAR'
        return False
    return True

def is_gdata_supported():
    try:
        __import__('gdata.service')
    except ImportError:
        print 'NO GDAT'
        return False
    return True

def is_pyfilesystem_supported():
    try:
        __import__('fs.opener')
    except ImportError:
        print 'NO FS'
        return False
    return True

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
        # patch the getpass module to bypass user input
        self.getpass_orig = getpass.getpass
        getpass.getpass = lambda *args, **kwargs: "abcdef"

    def tearDown(self):
        getpass.getpass = self.getpass_orig
        del self.getpass_orig

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

@unittest.skipUnless(is_dbus_supported(),
    "DBus needed for SecretServiceKeyring")
class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def environ(self):
        return dict(DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        print >> sys.stderr, "Testing SecretServiceKeyring, following password prompts are for this keyring"
        return keyring.backend.SecretServiceKeyring()

    def test_supported_no_module(self):
        with ImportKiller('dbus'):
            with Environ(**self.environ()):
                self.assertEqual(-1, self.keyring.supported())


def init_google_docs_keyring(client, can_create=True,
                             input_getter=raw_input):
    credentials = keyring.backend.BaseCredential('foo', 'bar')
    return keyring.backend.GoogleDocsKeyring(credentials, 
                                             'test_src',
                                             keyring.backend.NullCrypter(),
                                             client=client,
                                             can_create=can_create,
                                             input_getter=input_getter
                                            )

@unittest.skipUnless(is_gdata_supported(),
                     "Need Google Docs (gdata)")
class GoogleDocsKeyringTestCase(BackendBasicTests, unittest.TestCase):
    """Run all the standard tests on a new keyring"""

    def init_keyring(self):
        client = mocks.MockDocumentService()
        client.SetClientLoginToken('foo')
        return init_google_docs_keyring(client)

@unittest.skipUnless(is_gdata_supported(),
                     "Need Google Docs (gdata)")
class GoogleDocsKeyringInteractionTestCase(unittest.TestCase):
    """Additional tests for Google Doc interactions"""

    def _init_client(self, set_token=True):
        client = mocks.MockDocumentService()
        if set_token:
            client.SetClientLoginToken('interaction')
        return client

    def _init_keyring(self, client):
        self.keyring = init_google_docs_keyring(client)

    def _init_listfeed(self):
        listfeed = mocks.MockListFeed()
        listfeed._entry = [mocks.MockDocumentListEntry(),
                           mocks.MockDocumentListEntry()
                          ]
        return listfeed
    
    def _encode_data(self, data):
        return base64.urlsafe_b64encode(cPickle.dumps(data))

    def test_handles_auth_failure(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.BadAuthentication
        self._init_keyring(client)
        try:
            google_client = self.keyring.client
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_auth_error(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.Error
        self._init_keyring(client)
        try:
            google_client = self.keyring.client
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_login_captcha(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.CaptchaRequired
        client.captcha_url = 'a_captcha_url'
        client.captcha_token = 'token'
        self.get_input_called = False
        def _get_input(prompt):
            self.get_input_called = True
            delattr(client, '_login_err')
            return 'Foo'
        self.keyring = init_google_docs_keyring(client, input_getter=_get_input)
        google_client = self.keyring.client
        self.assertTrue(self.get_input_called, 'Should have got input')

    def test_retrieves_existing_keyring_with_and_without_bom(self):
        client = self._init_client()
        dummy_entries = dict(section1=dict(user1='pwd1'))
        no_utf8_bom_entries = self._encode_data(dummy_entries)
        client._request_response = dict(status=200, data=no_utf8_bom_entries)
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('section1', 'user1'), 'pwd1')

        utf8_bom_entries = codecs.BOM_UTF8 + no_utf8_bom_entries
        client._request_response = dict(status=200, data=utf8_bom_entries)
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('section1', 'user1'), 'pwd1')

    def test_handles_retrieve_failure(self):
        import gdata
        client = self._init_client()
        client._listfeed = self._init_listfeed()
        client._request_response = dict(status=400,
                                        reason='Data centre explosion')
        self._init_keyring(client)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_corrupt_retrieve(self):
        client = self._init_client()
        dummy_entries = dict(section1=dict(user1='pwd1'))
        client._request_response = dict(status=200, data='broken' + self._encode_data(dummy_entries))
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_no_create_if_requested(self):
        client = self._init_client()
        self.keyring = init_google_docs_keyring(client, can_create=False)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_no_set_if_create_folder_fails_on_new_keyring(self):
        import gdata
        client = self._init_client()
        client._create_folder_err = gdata.service.RequestError
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set in new keyring')
        try:
            self.keyring.set_password('service-a', 'user-A', 'password-A')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set after write fail')

    def test_no_set_if_write_fails_on_new_keyring(self):
        import gdata
        client = self._init_client()
        client._upload_err = gdata.service.RequestError
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set in new keyring')
        try:
            self.keyring.set_password('service-a', 'user-A', 'password-A')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set after write fail')

    def test_no_set_if_write_fails_on_existing_keyring(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionB=dict(user9='pwd9'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries)) 
        client._put_err = gdata.service.RequestError
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('sectionB', 'user9'), 'pwd9',
                        'Correct password should be set in existing keyring')
        try:
            self.keyring.set_password('sectionB', 'user9', 'Not the same pwd')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('sectionB', 'user9'), 'pwd9',
                        'Password should be unchanged after write fail')

    def test_writes_correct_data_to_google_docs(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteChk=dict(userWriteChk='pwd'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.keyring.set_password('sectionWriteChk',
                                  'userWritechk',
                                  'new_pwd')
        self.assertIsNotNone(client._put_data, 'Should have written data')
        self.assertEquals(
            'new_pwd',
            client._put_data.get('sectionWriteChk').get('userWritechk'),
            'Did not write updated password!')

    def test_handles_write_conflict_on_different_service(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictA=dict(
            userwriteConflictA='pwdwriteConflictA'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(gdata.service.RequestError,
                               {'status': '406',
                                'reason': 'Conflict'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictA',
                                      'userwriteConflictA'),
            'pwdwriteConflictA',
            'Correct password should be set in existing keyring')
        dummy_entries['diffSection'] = dict(foo='bar')
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        new_pwd = 'Not the same pwd'
        self.keyring.set_password('sectionWriteConflictA',
                                  'userwriteConflictA',
                                  new_pwd)

        self.assertEquals(self.keyring.get_password('sectionWriteConflictA',
                                                    'userwriteConflictA'),
                          new_pwd
        )
        self.assertEqual(1, client._put_count,
                         'Write not called after conflict resolution')

    def test_handles_write_conflict_on_same_service_and_username(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictB=dict(
            userwriteConflictB='pwdwriteConflictB'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = (gdata.service.RequestError,
                               {'status': '406',
                                'reason': 'Conflict'})
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictB',
                                      'userwriteConflictB'),
            'pwdwriteConflictB',
            'Correct password should be set in existing keyring')
        conflicting_dummy_entries = dict(sectionWriteConflictB=dict(
            userwriteConflictB='pwdwriteConflictC'))
        client._request_response = dict(status=200, data=self._encode_data(conflicting_dummy_entries))
        try:
            self.keyring.set_password('sectionWriteConflictB',
                                      'userwriteConflictB',
                                      'new_pwd')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass

    def test_handles_write_conflict_with_identical_change(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictC=dict(
            userwriteConflictC='pwdwriteConflictC'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(gdata.service.RequestError,
                               {'status': '406',
                                 'reason': 'Conflict'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictC',
                                      'userwriteConflictC'),
            'pwdwriteConflictC',
            'Correct password should be set in existing keyring')
        new_pwd = 'Not the same pwd'
        conflicting_dummy_entries = dict(sectionWriteConflictC=dict(
            userwriteConflictC=new_pwd))
        client._request_response = dict(status=200, data=self._encode_data(conflicting_dummy_entries))
        self.keyring.set_password('sectionWriteConflictC',
                                  'userwriteConflictC',
                                  new_pwd)
        self.assertEquals(self.keyring.get_password('sectionWriteConflictC',
                                                    'userwriteConflictC'),
                          new_pwd
        )

    def test_handles_broken_google_put_when_non_owner_update_fails(self):
        """Google Docs has a bug when putting to a non-owner
           see  GoogleDocsKeyring._save_keyring()
        """
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(
            gdata.service.RequestError,
                { 'status': '400',
                  'body': 'Sorry, there was an error saving the file. Please try again.',
                  'reason': 'Bad Request'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        new_pwd = 'newPwdBrokenPut'
        correct_read_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200,
                                        data=self._encode_data(correct_read_entries))
        try:
            self.keyring.set_password('sectionBrokenPut',
                                      'userBrokenPut',
                                      new_pwd)
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass

    def test_handles_broken_google_put_when_non_owner_update(self):
        """Google Docs has a bug when putting to a non-owner
           see  GoogleDocsKeyring._save_keyring()
        """
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(
            gdata.service.RequestError,
                { 'status': '400',
                  'body': 'Sorry, there was an error saving the file. Please try again.',
                  'reason': 'Bad Request'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        new_pwd = 'newPwdBrokenPut'
        correct_read_entries = dict(sectionBrokenPut=dict(
            userBrokenPut=new_pwd))
        client._request_response = dict(status=200,
                                        data=self._encode_data(correct_read_entries))
        self.keyring.set_password('sectionBrokenPut',
                                  'userBrokenPut',
                                  new_pwd)
        self.assertEquals(self.keyring.get_password('sectionBrokenPut',
                                                    'userBrokenPut'),
                          new_pwd)

    def test_uses_existing_folder(self):
        import gdata
        client = self._init_client()
        # should not happen
        client._create_folder_err = gdata.service.RequestError

        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                         'No password should be set in new keyring')
        client._listfeed = self._init_listfeed()
        self.keyring.set_password('service-a', 'user-A', 'password-A')
        self.assertIsNotNone(client._upload_data, 'Should have written data')
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'),
                         'password-A',
                         'Correct password should be set')

class ReverseCrypter(keyring.backend.Crypter):
    """Very silly crypter class"""

    def encrypt(self, value):
        return value[::-1]

    def decrypt(self, value):
        return value[::-1]

class PyfilesystemKeyringTests(BackendBasicTests):
    """Base class for Pyfilesystem tests"""

    def setUp(self):
        super(PyfilesystemKeyringTests, self).setUp()
        self.keyring = self.init_keyring()

    def tearDown(self):
        del self.keyring

    def test_encrypt_decrypt(self):
        password = random_string(20)
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedMemoryPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test in memory with no encryption"""

    keyring_filename = 'mem://unencrypted'

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedMemoryPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test in memory with no encryption"""

    keyring_filename = 'mem://some/sub/dir/unencrypted'

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedLocalPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with no encryption"""

    keyring_filename = '%s/keyring.cfg' %tempfile.mkdtemp()

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

    def test_handles_preexisting_keyring(self):
        from fs.opener import opener
        fs, path = opener.parse(self.keyring_filename, writeable=True)
        keyring_file = fs.open(path, 'wb')
        keyring_file.write(
            """[svc1]
user1 = cHdkMQ==
            """)
        keyring_file.close()
        pyf_keyring = keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)
        self.assertEquals('pwd1', pyf_keyring.get_password('svc1', 'user1'))

    def tearDown(self):
        del self.keyring
        if os.path.exists(self.keyring_filename):
            os.remove(self.keyring_filename)

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedLocalPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with no encryption"""

    keyring_dir = '%s//more/sub/dirs' %tempfile.mkdtemp()
    keyring_filename = '%s/keyring.cfg' %keyring_dir

    def init_keyring(self):

        if not os.path.exists(self.keyring_dir):
            os.makedirs(self.keyring_dir)
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedMemoryPyfilesystemKeyringTestCase(PyfilesystemKeyringTests,
                                                 unittest.TestCase):
    """Test in memory with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='mem://encrypted/keyring.cfg')

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedLocalPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='temp://keyring.cfg')

@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedLocalPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='temp://a/sub/dir/hierarchy/keyring.cfg')

@unittest.skipUnless(is_keyczar_supported(),
                     "Need Keyczar")
class KeyczarCrypterTestCase(unittest.TestCase):

    """Test the keyczar crypter"""

    def setUp(self):
        self._orig_keyczar = keyring.backend.keyczar
        keyring.backend.keyczar = mocks.MockKeyczar()

    def tearDown(self):
        keyring.backend.keyczar = self._orig_keyczar
        if keyring.backend.EnvironKeyczarCrypter.KEYSET_ENV_VAR in os.environ:
            del os.environ[keyring.backend.EnvironKeyczarCrypter.KEYSET_ENV_VAR]
        if keyring.backend.EnvironKeyczarCrypter.ENC_KEYSET_ENV_VAR in os\
        .environ:
            del os.environ[
                keyring.backend.EnvironKeyczarCrypter.ENC_KEYSET_ENV_VAR]

    def testKeyczarCrypterWithUnencryptedReader(self):
        """
        """
        location = 'bar://baz'
        kz_crypter = keyring.backend.KeyczarCrypter(location)
        self.assertEquals(location, kz_crypter.keyset_location)
        self.assertIsNone(kz_crypter.encrypting_keyset_location)
        self.assertIsInstance(kz_crypter.crypter, mocks.MockKeyczarCrypter)
        self.assertIsInstance(kz_crypter.crypter.reader, mocks.MockKeyczarReader)
        self.assertEquals(location, kz_crypter.crypter.reader.location)

    def testKeyczarCrypterWithEncryptedReader(self):
        """
        """
        location = 'foo://baz'
        encrypting_location = 'castle://aaargh'
        kz_crypter = keyring.backend.KeyczarCrypter(location, encrypting_location)
        self.assertEquals(location, kz_crypter.keyset_location)
        self.assertEquals(encrypting_location,
                          kz_crypter.encrypting_keyset_location)
        self.assertIsInstance(kz_crypter.crypter, mocks.MockKeyczarCrypter)
        self.assertIsInstance(kz_crypter.crypter.reader,
                              mocks.MockKeyczarEncryptedReader)
        self.assertEquals(location, kz_crypter.crypter.reader._reader.location)
        self.assertEquals(encrypting_location,
                          kz_crypter.crypter.reader._crypter.reader.location)

    def testKeyczarCrypterEncryptDecryptHandlesEmptyNone(self):
        location = 'castle://aargh'
        kz_crypter = keyring.backend.KeyczarCrypter(location)
        self.assertEquals('', kz_crypter.encrypt(''))
        self.assertEquals('', kz_crypter.encrypt(None))
        self.assertEquals('', kz_crypter.decrypt(''))
        self.assertEquals('', kz_crypter.decrypt(None))

    def testEnvironCrypterReadsCorrectValues(self):
        location = 'foo://baz'
        encrypting_location = 'castle://aaargh'
        kz_crypter = keyring.backend.EnvironKeyczarCrypter()
        os.environ[kz_crypter.KEYSET_ENV_VAR] = location
        self.assertEqual(location, kz_crypter.keyset_location)
        self.assertIsNone(kz_crypter.encrypting_keyset_location)
        os.environ[kz_crypter.ENC_KEYSET_ENV_VAR] = encrypting_location
        self.assertEqual(encrypting_location, kz_crypter.encrypting_keyset_location)

    def testEnvironCrypterThrowsExceptionOnMissingValues(self):
        location = 'foo://baz'
        encrypting_location = 'castle://aaargh'
        kz_crypter = keyring.backend.EnvironKeyczarCrypter()
        try:
            locn = kz_crypter.keyset_location
            self.assertTrue(False, msg="Should have thrown ValueError")
        except ValueError:
            # expected
            pass
        self.assertIsNone(kz_crypter.encrypting_keyset_location)

class MultipartKeyringWrapperTestCase(unittest.TestCase):

    """Test the wrapper that breaks passwords into smaller chunks"""

    class MockKeyring(keyring.backend.KeyringBackend):

        def __init__(self):
            self.passwords = {}

        def supported(self):
            return 'yes'

        def get_password(self, service, username):
            return self.passwords.get(service+username)

        def set_password(self, service, username, password):
            self.passwords[service+username] = password

    def testSupportedPassThru(self):
        kr = keyring.backend.MultipartKeyringWrapper(self.MockKeyring())
        self.assertEquals(kr.supported(), 'yes')

    def testMissingPassword(self):
        wrapped_kr = self.MockKeyring()
        kr = keyring.backend.MultipartKeyringWrapper(wrapped_kr)
        self.assertIsNone(kr.get_password('s1', 'u1'))

    def testSmallPasswordSetInSinglePart(self):
        wrapped_kr = self.MockKeyring()
        kr = keyring.backend.MultipartKeyringWrapper(wrapped_kr)
        kr.set_password('s1', 'u1', 'p1')
        self.assertEquals(wrapped_kr.passwords, {'s1u1':'p1'})
        # should be able to read it back
        self.assertEquals(kr.get_password('s1', 'u1'), 'p1')

    def testLargePasswordSetInMultipleParts(self):
        wrapped_kr = self.MockKeyring()
        kr = keyring.backend.MultipartKeyringWrapper(wrapped_kr,
                                                     max_password_size=2)
        kr.set_password('s2', 'u2', '0123456')
        self.assertEquals(wrapped_kr.passwords, {'s2u2':'01',
                                                 's2u2{{part_1}}':'23',
                                                 's2u2{{part_2}}':'45',
                                                 "s2u2{{part_3}}":'6'})

        # should be able to read it back
        self.assertEquals(kr.get_password('s2', 'u2'), '0123456')

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(OSXKeychainTestCase))
    suite.addTest(unittest.makeSuite(GnomeKeyringTestCase))
    suite.addTest(unittest.makeSuite(SecretServiceKeyringTestCase))
    suite.addTest(unittest.makeSuite(KDEWalletCanceledTestCase))
    suite.addTest(unittest.makeSuite(KDEKWalletTestCase))
    suite.addTest(unittest.makeSuite(KDEKWalletInQApplication))
    suite.addTest(unittest.makeSuite(UncryptedFileKeyringTestCase))
    suite.addTest(unittest.makeSuite(CryptedFileKeyringTestCase))
    suite.addTest(unittest.makeSuite(Win32CryptoKeyringTestCase))
    suite.addTest(unittest.makeSuite(WinVaultKeyringTestCase))
    suite.addTest(unittest.makeSuite(GoogleDocsKeyringTestCase))
    suite.addTest(unittest.makeSuite(GoogleDocsKeyringInteractionTestCase))
    suite.addTest(unittest.makeSuite(UnencryptedMemoryPyfilesystemKeyringNoSubDirTestCase))
    suite.addTest(unittest.makeSuite(UnencryptedMemoryPyfilesystemKeyringSubDirTestCase))
    suite.addTest(unittest.makeSuite(UnencryptedLocalPyfilesystemKeyringNoSubDirTestCase))
    suite.addTest(unittest.makeSuite(UnencryptedLocalPyfilesystemKeyringSubDirTestCase))
    suite.addTest(unittest.makeSuite(EncryptedMemoryPyfilesystemKeyringTestCase))
    suite.addTest(unittest.makeSuite(EncryptedLocalPyfilesystemKeyringNoSubDirTestCase))
    suite.addTest(unittest.makeSuite(EncryptedLocalPyfilesystemKeyringSubDirTestCase))
    suite.addTest(unittest.makeSuite(KeyczarCrypterTestCase))
    suite.addTest(unittest.makeSuite(MultipartKeyringWrapperTestCase))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
