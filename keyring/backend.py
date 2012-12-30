"""
backend.py

Keyring Backend implementations
"""

from __future__ import with_statement

import getpass
import os
import sys
import base64
import copy
import cPickle
import codecs
import subprocess
import re
import binascii

try:
    import io
except ImportError:
    # Support Python 2.4, 2.5
    import StringIO as io

try:
    import configparser
except ImportError:
    # Support Python 2.4-2.7
    import ConfigParser as configparser

from keyring.util.escape import escape as escape_for_ini
import keyring.util.escape
from keyring.util import properties
import keyring.util.platform
import keyring.py25compat
try:
    from keyczar import keyczar
except ImportError:
    pass

# use abstract base classes from the compat module
abc = keyring.py25compat.abc
# use json from the compat module
json = keyring.py25compat.json

class PasswordSetError(Exception):
    """Raised when the password can't be set.
    """

class InitError(Exception):
    """Raised when the keyring could not be initialised
    """

class KeyringBackendMeta(abc.ABCMeta):
    """
    A metaclass that's both an ABCMeta and a type that keeps a registry of
    all (non-abstract) types.
    """
    def __init__(cls, name, bases, dict):
        super(KeyringBackendMeta, cls).__init__(name, bases, dict)
        if not hasattr(cls, '_classes'):
            cls._classes = set()
        classes = cls._classes
        if not cls.__abstractmethods__:
            classes.add(cls)

class KeyringBackend(object):
    """The abstract base class of the keyring, every backend must implement
    this interface.
    """
    __metaclass__ = KeyringBackendMeta

    @abc.abstractmethod
    def supported(self):
        """Return if this keyring supports current environment:
        -1: not applicable
         0: suitable
         1: recommended
        """
        return -1

    @abc.abstractmethod
    def get_password(self, service, username):
        """Get password of the username for the service
        """
        return None

    @abc.abstractmethod
    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        raise PasswordSetError("reason")

class _ExtensionKeyring(KeyringBackend):
    """**deprecated**"""
    def __init__(self):
        try:
            self.keyring_impl = self._init_backend()
        except ImportError:
            # keyring is not installed properly
            self.keyring_impl = None

    def _init_backend(self):
        """Return the keyring implementation handler
        """
        return None

    def _recommend(self):
        """If this keyring is recommended on current environment.
        """
        return False

    def supported(self):
        """Override the supported() in KeyringBackend.
        """
        if self.keyring_impl is None:
            return -1
        elif self._recommend():
            return 1
        return 0

    def get_password(self, service, username):
        """Override the get_password() in KeyringBackend.
        """
        try:
            password = self.keyring_impl.password_get(service, username)
        except OSError:
            password = None
        return password

    def set_password(self, service, username, password):
        """Override the set_password() in KeyringBackend.
        """
        try:
            self.keyring_impl.password_set(service, username, password)
        except (OSError,):
            e = sys.exc_info()[1]
            raise PasswordSetError(e.message)

class OSXKeychain(KeyringBackend):
    """Mac OS X Keychain"""

    def supported(self):
        """Recommended for all OSX environment.
        """
        return sys.platform == 'darwin' or -1

    @staticmethod
    def set_password(service, username, password):
        if username is None:
            username = ''
        try:
            # set up the call for security.
            call = subprocess.Popen([
                    'security',
                    'add-generic-password',
                    '-a',
                    username,
                    '-s',
                    service,
                    '-w',
                    password,
                    '-U'
                ],
                stderr = subprocess.PIPE,
                stdout = subprocess.PIPE,
            )
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            # check return code.
            if code is not 0:
                raise PasswordSetError('Can\'t store password in keychain')
        except:
            raise PasswordSetError("Can't store password in keychain")

    @staticmethod
    def get_password(service, username):
        if username is None:
            username = ''
        try:
            # set up the call to security.
            call = subprocess.Popen([
                    'security',
                    'find-generic-password',
                    '-g',
                    '-a',
                    username,
                    '-s',
                    service
                ],
                stderr = subprocess.PIPE,
                stdout = subprocess.PIPE,
            )
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            if code is not 0:
                raise OSError("Can't fetch password from system")
            output = stderrdata
            # check for empty password.
            if output == 'password: \n':
                return ''
            # search for special password pattern.
            matches = re.search('password:(?P<hex>.*?)"(?P<pw>.*)"', output)
            if matches:
                hex = matches.group('hex').strip()
                pw = matches.group('pw')
                if hex:
                    # it's a weird hex password, decode it.
                    return binascii.unhexlify(hex[2:])
                else:
                    # it's a normal password, send it back.
                    return pw
            # nothing was found, it doesn't exist.
            return None
        except:
            return None

class GnomeKeyring(KeyringBackend):
    """Gnome Keyring"""

    # Name of the keyring to store the passwords in.
    # Use None for the default keyring.
    KEYRING_NAME = None

    def supported(self):
        try:
            __import__('gnomekeyring')
        except ImportError:
            return -1
        else:
            if ("GNOME_KEYRING_CONTROL" in os.environ and
                "DISPLAY" in os.environ and
                "DBUS_SESSION_BUS_ADDRESS" in os.environ):
                return 1
            else:
                return 0

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        import gnomekeyring

        service = self._safe_string(service)
        username = self._safe_string(username)
        try:
            items = gnomekeyring.find_network_password_sync(username, service)
        except gnomekeyring.NoMatchError:
            return None
        except gnomekeyring.CancelledError:
            # The user pressed "Cancel" when prompted to unlock their keyring.
            return None

        assert len(items) == 1, 'no more than one entry should ever match'
        return items[0]['password']

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        import gnomekeyring

        service = self._safe_string(service)
        username = self._safe_string(username)
        password = self._safe_string(password)
        try:
            gnomekeyring.item_create_sync(
                self.KEYRING_NAME, gnomekeyring.ITEM_NETWORK_PASSWORD,
                "Password for '%s' on '%s'" % (username, service),
                {'user': username, 'domain': service},
                password, True)
        except gnomekeyring.CancelledError:
            # The user pressed "Cancel" when prompted to unlock their keyring.
            raise PasswordSetError("cancelled by user")

    def _safe_string(self, source, encoding='utf-8'):
        """Convert unicode to string as gnomekeyring barfs on unicode"""
        if isinstance(source, unicode):
            return source.encode(encoding)
        return str(source)

class SecretServiceKeyring(KeyringBackend):
    """Secret Service Keyring"""

    def supported(self):
        try:
            import dbus
        except ImportError:
            return -1
        try:
            bus = dbus.SessionBus()
            bus.get_object('org.freedesktop.secrets',
                '/org/freedesktop/secrets')
        except dbus.exceptions.DBusException:
            return -1
        else:
            return 1

    def _str_to_dbus_str(self, s, strict=False):
        """Given a string, do our best to turn it into a unicode compatible
        object.
        """
        if issubclass(s.__class__, unicode):
            # It's already unicode, no problem.
            return s

        # It's not unicode.  Convert it to a unicode string.
        try:
            return unicode(s)
        except UnicodeEncodeError:
            logger.exception("Failed to convert '%s' to unicode" % s)
            if strict:
                raise
            else:
                return unicode(s, errors='replace')

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        import dbus
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        bus = dbus.SessionBus()
        service_obj = bus.get_object('org.freedesktop.secrets',
            '/org/freedesktop/secrets')
        service_iface = dbus.Interface(service_obj,
            'org.freedesktop.Secret.Service')
        unlocked, locked = service_iface.SearchItems(
            {"username": username, "service": service})
        _, session = service_iface.OpenSession("plain", "")
        no_longer_locked, prompt = service_iface.Unlock(locked)
        assert prompt == "/"
        secrets = service_iface.GetSecrets(unlocked + locked, session,
            byte_arrays=True)
        for item_path, secret in secrets.iteritems():
            return unicode(secret[2])
        return None

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        import dbus
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        password = self._str_to_dbus_str(password)
        bus = dbus.SessionBus()
        service_obj = bus.get_object('org.freedesktop.secrets',
            '/org/freedesktop/secrets')
        service_iface = dbus.Interface(service_obj,
            'org.freedesktop.Secret.Service')
        collection_obj = bus.get_object(
            'org.freedesktop.secrets',
            '/org/freedesktop/secrets/aliases/default')
        collection = dbus.Interface(collection_obj,
            'org.freedesktop.Secret.Collection')
        attributes = {
            "service": service,
            "username": username
            }
        _, session = service_iface.OpenSession("plain", "")

        secret = dbus.Struct(
            (session, "", dbus.ByteArray(password), "application/octet-stream"))
        properties = {
            "org.freedesktop.Secret.Item.Label": "%s @ %s" % (
                username, service),
            "org.freedesktop.Secret.Item.Attributes": attributes}
        (item, prompt) = collection.CreateItem(properties, secret,
            True)
        assert prompt == "/"


kwallet = None

def open_kwallet(kwallet_module=None, qt_module=None):

    # If we specified the kwallet_module and/or qt_module, surely we won't need
    # the cached kwallet object...
    if kwallet_module is None and qt_module is None:
        global kwallet
        if not kwallet is None:
            return kwallet

    # Allow for the injection of module-like objects for testing purposes.
    if kwallet_module is None:
        kwallet_module = KWallet.Wallet
    if qt_module is None:
        qt_module = QtGui

    # KDE wants us to instantiate an application object.
    app = None
    if qt_module.qApp.instance() == None:
        app = qt_module.QApplication([])
    try:
        window = qt_module.QWidget()
        kwallet = kwallet_module.openWallet(
            kwallet_module.NetworkWallet(),
            window.winId(),
            kwallet_module.Synchronous)
        if kwallet is not None:
            if not kwallet.hasFolder('Python'):
                kwallet.createFolder('Python')
            kwallet.setFolder('Python')
            return kwallet
    finally:
        if app:
            app.exit()


try:
    from PyKDE4.kdeui import KWallet
    from PyQt4 import QtGui
except ImportError:
    kwallet_support = False
else:
    kwallet_support = True


class KDEKWallet(KeyringBackend):
    """KDE KWallet"""

    def supported(self):
        if kwallet_support and 'KDE_SESSION_UID' in os.environ:
            return 1
        elif kwallet_support:
            return 0
        else:
            return -1

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        key = username + '@' + service
        network = KWallet.Wallet.NetworkWallet()
        wallet = open_kwallet()
        if wallet.keyDoesNotExist(network, 'Python', key):
            return None

        result = wallet.readPassword(key)[1]
        # The string will be a PyQt4.QtCore.QString, so turn it into a unicode
        # object.
        return unicode(result)

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        wallet = open_kwallet()
        wallet.writePassword(username+'@'+service, password)

class BasicFileKeyring(KeyringBackend):
    """
    BasicFileKeyring is a file-based implementation of keyring.

    This keyring stores the password directly in the file and provides methods
    which may be overridden by subclasses to support
    encryption and decryption. The encrypted payload is stored in base64
    format.
    """

    @properties.NonDataProperty
    def file_path(self):
        """
        The path to the file where passwords are stored. This property
        may be overridden by the subclass or at the instance level.
        """
        return os.path.join(keyring.util.platform.data_root(), self.filename)

    @abc.abstractproperty
    def filename(self):
        """The filename used to store the passwords.
        """
        pass

    @abc.abstractmethod
    def encrypt(self, password):
        """Encrypt the password.
        """
        pass

    @abc.abstractmethod
    def decrypt(self, password_encrypted):
        """Decrypt the password.
        """
        pass

    def get_password(self, service, username):
        """Read the password from the file.
        """
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # load the passwords from the file
        config = configparser.RawConfigParser()
        if os.path.exists(self.file_path):
            config.read(self.file_path)

        # fetch the password
        try:
            password_base64 = config.get(service, username).encode()
            # decode with base64
            password_encrypted = base64.decodestring(password_base64)
            # decrypted the password
            password = self.decrypt(password_encrypted).decode('utf-8')
        except (configparser.NoOptionError, configparser.NoSectionError):
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password in the file.
        """
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # encrypt the password
        password_encrypted = self.encrypt(password.encode('utf-8'))
        # encode with base64
        password_base64 = base64.encodestring(password_encrypted).decode()

        # ensure the file exists
        self._ensure_file_path()

        # load the keyring from the disk
        config = configparser.RawConfigParser()
        config.read(self.file_path)

        # update the keyring with the password
        if not config.has_section(service):
            config.add_section(service)
        config.set(service, username, password_base64)

        # save the keyring back to the file
        config_file = open(self.file_path, 'w')
        try:
            config.write(config_file)
        finally:
            config_file.close()

    def _ensure_file_path(self):
        """
        Ensure the storage path exists.
        If it doesn't, create it with "go-rwx" permissions.
        """
        storage_root = os.path.dirname(self.file_path)
        if storage_root and not os.path.isdir(storage_root):
            os.makedirs(storage_root)
        if not os.path.isfile(self.file_path):
            # create the file without group/world permissions
            with open(self.file_path, 'w'):
                pass
            user_read_write = 0600
            os.chmod(self.file_path, user_read_write)


class UncryptedFileKeyring(BasicFileKeyring):
    """Uncrypted File Keyring"""

    filename = 'keyring_pass.cfg'

    def encrypt(self, password):
        """Directly return the password itself.
        """
        return password

    def decrypt(self, password_encrypted):
        """Directly return encrypted password.
        """
        return password_encrypted

    def supported(self):
        """Applicable for all platforms, but do not recommend.
        """
        return 0

class CryptedFileKeyring(BasicFileKeyring):
    """PyCrypto File Keyring"""

    # a couple constants
    block_size = 32
    pad_char = '0'

    filename = 'crypted_pass.cfg'

    def supported(self):
        """Applicable for all platforms, but not recommend"
        """
        try:
            __import__('Crypto.Cipher.AES')
            __import__('Crypto.Protocol.KDF')
            __import__('Crypto.Random')
            if not json:
                raise AssertionError("JSON implementation needed (install "
                    "simplejson)")
            status = 0
        except (ImportError, AssertionError):
            status = -1
        return status

    @properties.NonDataProperty
    def keyring_key(self):
        # _unlock or _init_file will set the key or raise an exception
        if self._check_file():
            self._unlock()
        else:
            self._init_file()
        return self.keyring_key

    def _get_new_password(self):
        while True:
            password = getpass.getpass(
                "Please set a password for your new keyring: ")
            confirm = getpass.getpass('Please confirm the password: ')
            if password != confirm:
                sys.stderr.write("Error: Your passwords didn't match\n")
                continue
            if '' == password.strip():
                # forbid the blank password
                sys.stderr.write("Error: blank passwords aren't allowed.\n")
                continue
            return password

    def _init_file(self):
        """
        Initialize a new password file and set the reference password.
        """
        self.keyring_key = self._get_new_password()
        # set a reference password, used to check that the password provided
        #  matches for subsequent checks.
        self.set_password('keyring-setting', 'password reference',
            'password reference value')

    def _check_file(self):
        """
        Check if the file exists and has the expected password reference.
        """
        if not os.path.exists(self.file_path):
            return False
        self._migrate()
        config = configparser.RawConfigParser()
        config.read(self.file_path)
        try:
            config.get(
                escape_for_ini('keyring-setting'),
                escape_for_ini('password reference'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            return False
        return True

    def _unlock(self):
        """
        Unlock this keyring by getting the password for the keyring from the
        user.
        """
        self.keyring_key = getpass.getpass(
            'Please enter password for encrypted keyring: ')
        try:
            ref_pw = self.get_password('keyring-setting', 'password reference')
            assert ref_pw == 'password reference value'
        except AssertionError:
            self._lock()
            raise ValueError("Incorrect Password")

    def _lock(self):
        """
        Remove the keyring key from this instance.
        """
        del self.keyring_key

    def _create_cipher(self, password, salt, IV):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Cipher import AES
        pw = PBKDF2(password, salt, dkLen=self.block_size)
        return AES.new(pw[:self.block_size], AES.MODE_CFB, IV)

    def encrypt(self, password):
        from Crypto.Random import get_random_bytes
        salt = get_random_bytes(self.block_size)
        from Crypto.Cipher import AES
        IV = get_random_bytes(AES.block_size)
        cipher = self._create_cipher(self.keyring_key, salt, IV)
        password_encrypted = cipher.encrypt('pw:' + password)
        # Serialize the salt, IV, and encrypted password in a secure format
        data = dict(
            salt=salt, IV=IV, password_encrypted=password_encrypted,
        )
        for key in data:
            data[key] = data[key].encode('base64')
        return json.dumps(data)

    def decrypt(self, password_encrypted):
        # unpack the encrypted payload
        data = json.loads(password_encrypted)
        for key in data:
            data[key] = data[key].decode('base64')
        cipher = self._create_cipher(self.keyring_key, data['salt'],
            data['IV'])
        plaintext = cipher.decrypt(data['password_encrypted'])
        assert plaintext.startswith('pw:')
        return plaintext[3:]

    def _migrate(self, keyring_password=None):
        """
        Convert older keyrings to the current format.
        """

class Win32CryptoKeyring(BasicFileKeyring):
    """Win32 Cryptography Keyring"""

    filename = 'wincrypto_pass.cfg'

    def __init__(self):
        super(Win32CryptoKeyring, self).__init__()

        try:
            from backends import win32_crypto
            self.crypt_handler = win32_crypto
        except ImportError:
            self.crypt_handler = None

    def supported(self):
        """Recommended when other Windows backends are unavailable
        """
        recommended = select_windows_backend()
        if recommended == None:
            return -1
        elif recommended == 'file':
            return 1
        else:
            return 0

    def encrypt(self, password):
        """Encrypt the password using the CryptAPI.
        """
        return self.crypt_handler.encrypt(password)

    def decrypt(self, password_encrypted):
        """Decrypt the password using the CryptAPI.
        """
        return self.crypt_handler.decrypt(password_encrypted)


class WinVaultKeyring(KeyringBackend):
    """
    WinVaultKeyring stores encrypted passwords using the Windows Credential
    Manager.

    Requires pywin32

    This backend does some gymnastics to simulate multi-user support,
    which WinVault doesn't support natively. See
    https://bitbucket.org/kang/python-keyring-lib/issue/47/winvaultkeyring-only-ever-returns-last#comment-731977
    for details on the implementation, but here's the gist:

    Passwords are stored under the service name unless there is a collision
    (another password with the same service name but different user name),
    in which case the previous password is moved into a compound name:
    {username}@{service}
    """
    def __init__(self):
        super(WinVaultKeyring, self).__init__()
        try:
            import pywintypes
            import win32cred
            self.win32cred = win32cred
            self.pywintypes = pywintypes
        except ImportError:
            self.win32cred = None

    def supported(self):
        """Default Windows backend, when it is available
        """
        recommended = select_windows_backend()
        if recommended == None:
            return -1
        elif recommended == 'cred':
            return 1
        else:
            return 0

    @staticmethod
    def _compound_name(username, service):
        return keyring.util.escape.u('%(username)s@%(service)s') % vars()

    def get_password(self, service, username):
        # first attempt to get the password under the service name
        res = self._get_password(service)
        if not res or res['UserName'] != username:
            # It wasn't found so attempt to get it with the compound name
            res = self._get_password(self._compound_name(username, service))
        if not res:
            return None
        blob = res['CredentialBlob']
        return blob.decode('utf-16')

    def _get_password(self, target):
        try:
            res = self.win32cred.CredRead(
                Type=self.win32cred.CRED_TYPE_GENERIC,
                TargetName=target,
            )
        except (self.pywintypes.error,):
            e = sys.exc_info()[1]
            if e.winerror == 1168 and e.funcname == 'CredRead': # not found
                return None
            raise
        return res

    def set_password(self, service, username, password):
        existing_pw = self._get_password(service)
        if existing_pw:
            # resave the existing password using a compound target
            existing_username = existing_pw['UserName']
            target = self._compound_name(existing_username, service)
            self._set_password(target, existing_username,
                existing_pw['CredentialBlob'].decode('utf-16'))
        self._set_password(service, username, unicode(password))

    def _set_password(self, target, username, password):
        credential = dict(Type=self.win32cred.CRED_TYPE_GENERIC,
                          TargetName=target,
                          UserName=username,
                          CredentialBlob=password,
                          Comment="Stored using python-keyring",
                          Persist=self.win32cred.CRED_PERSIST_ENTERPRISE)
        self.win32cred.CredWrite(credential, 0)

    def delete_password(self, service, username):
        compound = self._compound_name(username, service)
        for target in service, compound:
            existing_pw = self._get_password(target)
            if existing_pw and existing_pw['UserName'] == username:
                self._delete_password(target)

    def _delete_password(self, target):
        self.win32cred.CredDelete(
            Type=self.win32cred.CRED_TYPE_GENERIC,
            TargetName=target,
        )

class Win32CryptoRegistry(KeyringBackend):
    """Win32CryptoRegistry is a keyring which use Windows CryptAPI to encrypt
    the user's passwords and store them under registry keys
    """
    def __init__(self):
        super(Win32CryptoRegistry, self).__init__()

        try:
            from backends import win32_crypto
            __import__('_winreg')
            self.crypt_handler = win32_crypto
        except ImportError:
            self.crypt_handler = None

    def supported(self):
        """Return if this keyring supports current enviroment.
        -1: not applicable
         0: suitable
         1: recommended
        """
        recommended = select_windows_backend()
        if recommended == None:
            return -1
        elif recommended == 'reg':
            return 1
        else:
            return 0

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        from _winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx
        try:
            # fetch the password
            key = r'Software\%s\Keyring' % service
            hkey = OpenKey(HKEY_CURRENT_USER, key)
            password_base64 = QueryValueEx(hkey, username)[0]
            # decode with base64
            password_encrypted = base64.decodestring(password_base64)
            # decrypted the password
            password = self.crypt_handler.decrypt(password_encrypted)
        except EnvironmentError:
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password to the registry
        """
        # encrypt the password
        password_encrypted = self.crypt_handler.encrypt(password)
        # encode with base64
        password_base64 = base64.encodestring(password_encrypted)

        # store the password
        from _winreg import HKEY_CURRENT_USER, CreateKey, SetValueEx, REG_SZ
        hkey = CreateKey(HKEY_CURRENT_USER, r'Software\%s\Keyring' % service)
        SetValueEx(hkey, username, 0, REG_SZ, password_base64)

def select_windows_backend():
    if os.name != 'nt':
        return None
    major, minor, build, platform, text = sys.getwindowsversion()
    try:
        __import__('pywintypes')
        __import__('win32cred')
        if (major, minor) >= (5, 1):
            # recommend for windows xp+
            return 'cred'
    except ImportError:
        pass
    try:
        __import__('keyring.backends.win32_crypto')
        __import__('_winreg')
        if (major, minor) >= (5, 0):
            # recommend for windows 2k+
            return 'reg'
    except ImportError:
        pass
    try:
        __import__('keyring.backends.win32_crypto')
        return 'file'
    except ImportError:
        pass
    return None

class GoogleDocsKeyring(KeyringBackend):
    """Backend that stores keyring on Google Docs.
       Note that login and any other initialisation is deferred until it is
       actually required to allow this keyring class to be added to the
       global _all_keyring list.
    """

    keyring_title = 'GoogleKeyring'
    # status enums
    OK = 1
    FAIL = 0
    CONFLICT = -1

    def __init__(self, credential, source, crypter,
                 collection=None, client=None,
                 can_create=True, input_getter=raw_input
                ):
        try:
            DocsService = (__import__('gdata.docs.service')
                .docs.service.DocsService)
        except ImportError:
            return

        self.credential = credential
        self.crypter = crypter
        self.source = source
        self._collection = collection
        self.can_create = can_create
        self.input_getter = input_getter
        self._keyring_dict = None

        if not client:
            self._client = DocsService()
        else:
            self._client = client

        self._client.source = source
        self._client.ssl = True
        self._login_reqd = True

    def supported(self):
        """Return if this keyring supports current environment:
        -1: not applicable
         0: suitable
         1: recommended
        """
        try:
            __import__('gdata.docs.service')
        except ImportError:
            return -1
        return 0

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        result = self._get_entry(self._keyring, service, username)
        if result:
            result = self._decrypt(result)
        return result

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        password = self._encrypt(password or '')
        keyring_working_copy = copy.deepcopy(self._keyring)
        service_entries = keyring_working_copy.get(service)
        if not service_entries:
            service_entries = {}
            keyring_working_copy[service] = service_entries
        service_entries[username] = password
        save_result = self._save_keyring(keyring_working_copy)
        if save_result == self.OK:
            self._keyring_dict = keyring_working_copy
            return
        elif save_result == self.CONFLICT:
            # check if we can avoid updating
            self.docs_entry, keyring_dict = self._read()
            existing_pwd = self._get_entry(self._keyring, service, username)
            conflicting_pwd = self._get_entry(keyring_dict, service, username)
            if conflicting_pwd == password:
                # if someone else updated it to the same value then we are done
                self._keyring_dict = keyring_working_copy
                return
            elif conflicting_pwd is None or conflicting_pwd == existing_pwd:
                # if doesn't already exist or is unchanged then update it
                new_service_entries = keyring_dict.get(service, {})
                new_service_entries[username] = password
                keyring_dict[service] = new_service_entries
                save_result = self._save_keyring(keyring_dict)
                if save_result == self.OK:
                    self._keyring_dict = keyring_dict
                    return
                else:
                    raise PasswordSetError(
                        'Failed write after conflict detected')
            else:
                raise PasswordSetError(
                    'Conflict detected, service:%s and username:%s was '\
                    'set to a different value by someone else' %(service,
                                                                 username))

        raise PasswordSetError('Could not save keyring')

    @property
    def client(self):
        if not self._client.GetClientLoginToken():
            import gdata
            try:
                self._client.ClientLogin(self.credential.username,
                                         self.credential.password,
                                         self._client.source)
            except gdata.service.CaptchaRequired:
                sys.stdout.write('Please visit ' + self._client.captcha_url)
                answer = self.input_getter('Answer to the challenge? ')
                self._client.email = self.credential.username
                self._client.password = self.credential.password
                self._client.ClientLogin(
                    self.credential.username,
                    self.credential.password,
                    self._client.source,
                    captcha_token=self._client.captcha_token,
                    captcha_response=answer)
            except gdata.service.BadAuthentication:
                raise InitError('Users credential were unrecognized')
            except gdata.service.Error:
                raise InitError('Login Error')

        return self._client

    @property
    def collection(self):
        return self._collection or self.credential.username.split('@')[0]

    @property
    def _keyring(self):
        if self._keyring_dict is None:
            self.docs_entry, self._keyring_dict = self._read()
        return self._keyring_dict

    def _get_entry(self, keyring_dict, service, username):
        result = None
        service_entries = keyring_dict.get(service)
        if service_entries:
            result = service_entries.get(username)
        return result

    def _decrypt(self, value):
        if not value:
            return ''
        return self.crypter.decrypt(value)

    def _encrypt(self, value):
        if not value:
            return ''
        return self.crypter.encrypt(value)

    def _get_doc_title(self):
        return '%s' %self.keyring_title

    def _read(self):
        from gdata.docs.service import DocumentQuery
        import gdata
        title_query = DocumentQuery(categories=[self.collection])
        title_query['title'] = self._get_doc_title()
        title_query['title-exact'] = 'true'
        docs = self.client.QueryDocumentListFeed(title_query.ToUri())

        if not docs.entry:
            if self.can_create:
                docs_entry = None
                keyring_dict = {}
            else:
                raise InitError(
                    '%s not found in %s and create not permitted'
                    %(self._get_doc_title(), self.collection))
        else:
            docs_entry = docs.entry[0]
            file_contents = ''
            try:
                url = docs_entry.content.src
                url += '&exportFormat=txt'
                server_response = self.client.request('GET', url)
                if server_response.status != 200:
                    raise InitError(
                        'Could not read existing Google Docs keyring')
                file_contents = server_response.read()
                if file_contents.startswith(codecs.BOM_UTF8):
                    file_contents = file_contents[len(codecs.BOM_UTF8):]
                keyring_dict = cPickle.loads(base64.urlsafe_b64decode(
                    file_contents.decode('string-escape')))
            except cPickle.UnpicklingError, ex:
                raise InitError(
                    'Could not unpickle existing Google Docs keyring', ex)
            except TypeError, ex:
                raise InitError(
                    'Could not decode existing Google Docs keyring', ex)

        return docs_entry, keyring_dict

    def _save_keyring(self, keyring_dict):
        """Helper to actually write the keyring to Google"""
        import gdata
        result = self.OK
        file_contents = base64.urlsafe_b64encode(cPickle.dumps(keyring_dict))
        try:
            if self.docs_entry:
                extra_headers = {'Content-Type': 'text/plain',
                                 'Content-Length': len(file_contents)}
                self.docs_entry = self.client.Put(
                    file_contents,
                    self.docs_entry.GetEditMediaLink().href,
                    extra_headers=extra_headers
                    )
            else:
                from gdata.docs.service import DocumentQuery
                # check for existence of folder, create if required
                folder_query = DocumentQuery(categories=['folder'])
                folder_query['title'] = self.collection
                folder_query['title-exact'] = 'true'
                docs = self.client.QueryDocumentListFeed(folder_query.ToUri())
                if docs.entry:
                    folder_entry = docs.entry[0]
                else:
                    folder_entry = self.client.CreateFolder(self.collection)
                file_handle = keyring.py25compat.BytesIO(file_contents)
                media_source = gdata.MediaSource(
                    file_handle=file_handle,
                    content_type='text/plain',
                    content_length=len(file_contents),
                    file_name='temp')
                self.docs_entry = self.client.Upload(
                    media_source,
                    self._get_doc_title(),
                    folder_or_uri=folder_entry
                )
        except gdata.service.RequestError, ex:
            try:
                if ex.message['reason'].lower().find('conflict') != -1:
                    result = self.CONFLICT
                else:
                    # Google docs has a bug when updating a shared document
                    # using PUT from any account other that the owner.
                    # It returns an error 400 "Sorry, there was an error saving the file. Please try again"
                    # *despite* actually updating the document!
                    # Workaround by re-reading to see if it actually updated
                    if ex.message['body'].find(
                        'Sorry, there was an error saving the file') != -1:
                        new_docs_entry, new_keyring_dict = self._read()
                        if new_keyring_dict == keyring_dict:
                            result = self.OK
                        else:
                            result = self.FAIL
                    else:
                        result = self.FAIL
            except:
                result = self.FAIL

        return result

class Credential(object):
    """Abstract class to manage credentials
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def username(self):
        return None

    @abc.abstractproperty
    def password(self):
        return None

class BaseCredential(Credential):
    """Simple credentials implementation
    """

    def __init__(self, username, password):
        self._username = username
        self._password = password

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

class EnvironCredential(Credential):
    """Source credentials from environment variables.
       Actual sourcing is deferred until requested.
    """

    def __init__(self, user_env_var, pwd_env_var):
        self.user_env_var = user_env_var
        self.pwd_env_var = pwd_env_var

    def _get_env(self, env_var):
        """Helper to read an environment variable
        """
        value = os.environ.get(env_var)
        if not value:
            raise ValueError('Missing environment variable:%s' %env_var)
        return value

    @property
    def username(self):
        return self._get_env(self.user_env_var)

    @property
    def password(self):
        return self._get_env(self.pwd_env_var)

class GoogleEnvironCredential(EnvironCredential):
    """Retrieve credentials from specifically named environment variables
    """

    def __init__(self):
        super(GoogleEnvironCredential, self).__init__(
            'GOOGLE_KEYRING_USER',
            'GOOGLE_KEYRING_PASSWORD')

class Crypter(object):
    """Base class providing encryption and decryption
    """

    @abc.abstractmethod
    def encrypt(self, value):
        """Encrypt the value.
        """
        pass

    @abc.abstractmethod
    def decrypt(self, value):
        """Decrypt the value.
        """
        pass

class NullCrypter(Crypter):
    """A crypter that does nothing
    """

    def encrypt(self, value):
        return value

    def decrypt(self, value):
        return value

class BaseKeyczarCrypter(Crypter):
    """Base Keyczar keyset encryption and decryption.
       The keyset initialisation is deferred until required.
    """

    @abc.abstractproperty
    def keyset_location(self):
        """Location for the main keyset that may be encrypted or not"""
        pass

    @abc.abstractproperty
    def encrypting_keyset_location(self):
        """Location for the encrypting keyset.
           Use None to indicate that the main keyset is not encrypted
        """
        pass

    @property
    def crypter(self):
        """The actual keyczar crypter"""
        if not hasattr(self, '_crypter'):
            # initialise the Keyczar keysets
            if not self.keyset_location:
                raise ValueError('No encrypted keyset location!')
            reader = keyczar.readers.CreateReader(self.keyset_location)
            if self.encrypting_keyset_location:
                encrypting_keyczar = keyczar.Crypter.Read(
                    self.encrypting_keyset_location)
                reader = keyczar.readers.EncryptedReader(reader,
                                                         encrypting_keyczar)
            self._crypter = keyczar.Crypter(reader)
        return self._crypter

    def encrypt(self, value):
        """Encrypt the value.
        """
        if not value:
            return ''
        return self.crypter.Encrypt(value)

    def decrypt(self, value):
        """Decrypt the value.
        """
        if not value:
            return ''
        return self.crypter.Decrypt(value)

class KeyczarCrypter(BaseKeyczarCrypter):
    """A Keyczar crypter using locations specified in the constructor
    """

    def __init__(self, keyset_location, encrypting_keyset_location=None):
        self._keyset_location = keyset_location
        self._encrypting_keyset_location = encrypting_keyset_location

    @property
    def keyset_location(self):
        return self._keyset_location

    @property
    def encrypting_keyset_location(self):
        return self._encrypting_keyset_location

class EnvironKeyczarCrypter(BaseKeyczarCrypter):
    """A Keyczar crypter using locations specified by environment vars
    """

    KEYSET_ENV_VAR = 'KEYRING_KEYCZAR_ENCRYPTED_LOCATION'
    ENC_KEYSET_ENV_VAR = 'KEYRING_KEYCZAR_ENCRYPTING_LOCATION'

    @property
    def keyset_location(self):
        val = os.environ.get(self.KEYSET_ENV_VAR)
        if not val:
            raise ValueError('%s environment value not set' %
                             self.KEYSET_ENV_VAR)
        return val

    @property
    def encrypting_keyset_location(self):
        return os.environ.get(self.ENC_KEYSET_ENV_VAR)

class EnvironGoogleDocsKeyring(GoogleDocsKeyring):
    """Google Docs keyring using keyczar initialized from environment
    variables
    """

    def __init__(self):
        crypter = EnvironKeyczarCrypter()
        credential = GoogleEnvironCredential()
        source = os.environ.get('GOOGLE_KEYRING_SOURCE')
        super(EnvironGoogleDocsKeyring, self).__init__(
            credential, source, crypter)

    def supported(self):
        """Return if this keyring supports current environment:
        -1: not applicable
         0: suitable
         1: recommended
        """
        try:
            from keyczar import keyczar
            return super(EnvironGoogleDocsKeyring, self).supported()
        except ImportError:
            return -1

class BasicPyfilesystemKeyring(KeyringBackend):
    """BasicPyfilesystemKeyring is a Pyfilesystem-based implementation of
    keyring.

    It stores the password directly in the file, and supports
    encryption and decryption. The encrypted password is stored in base64
    format.
    Being based on Pyfilesystem the file can be local or network-based and
    served by any of the filesystems supported by Pyfilesystem including Amazon
    S3, FTP, WebDAV, memory and more.
    """

    _filename = 'keyring_pyf_pass.cfg'

    def __init__(self, crypter, filename=None, can_create=True,
                 cache_timeout=None):
        super(BasicPyfilesystemKeyring, self).__init__()
        self._crypter = crypter
        self._filename = (filename or
                          os.path.join(keyring.util.platform.data_root(),
                                       self.__class__._filename))
        self._can_create = can_create
        self._cache_timeout = cache_timeout

    @properties.NonDataProperty
    def file_path(self):
        """
        The path to the file where passwords are stored. This property
        may be overridden by the subclass or at the instance level.
        """
        return os.path.join(keyring.util.platform.data_root(), self.filename)

    @property
    def filename(self):
        """The filename used to store the passwords.
        """
        return self._filename

    def encrypt(self, password):
        """Encrypt the password.
        """
        if not password or not self._crypter:
            return password or ''
        return self._crypter.encrypt(password)

    def decrypt(self, password_encrypted):
        """Decrypt the password.
        """
        if not password_encrypted or not self._crypter:
            return password_encrypted or ''
        return self._crypter.decrypt(password_encrypted)

    def _open(self, mode='rb'):
        """Open the password file in the specified mode
        """
        import fs.opener
        import fs.errors
        import fs.path
        import fs.remote
        open_file = None
        writeable = 'w' in mode or 'a' in mode or '+' in mode
        try:
            # NOTE: currently the MemOpener does not split off any filename
            #       which causes errors on close()
            #       so we add a dummy name and open it separately
            if (self.filename.startswith('mem://') or
                self.filename.startswith('ram://')):
                open_file = fs.opener.fsopendir(self.filename).open('kr.cfg',
                                                                    mode)
            else:
                if not hasattr(self, '_pyfs'):
                    # reuse the pyfilesystem and path
                    self._pyfs, self._path = fs.opener.opener.parse(self.filename,
                                               writeable=writeable)
                    # cache if permitted
                    if self._cache_timeout is not None:
                        self._pyfs = fs.remote.CacheFS(
                            self._pyfs, cache_timeout=self._cache_timeout)
                open_file = self._pyfs.open(self._path, mode)
        except fs.errors.ResourceNotFoundError:
            if self._can_create:
                segments = fs.opener.opener.split_segments(self.filename)
                if segments:
                    # this seems broken, but pyfilesystem uses it, so we must
                    fs_name, credentials, url1, url2, path = segments.groups()
                    assert fs_name, 'Should be a remote filesystem'
                    host = ''
                    # allow for domain:port
                    if ':' in url2:
                        split_url2 = url2.split('/', 1)
                        if len(split_url2) > 1:
                            url2 = split_url2[1]
                        else:
                            url2 = ''
                        host = split_url2[0]
                    pyfs = fs.opener.opener.opendir('%s://%s' %(fs_name, host))
                    # cache if permitted
                    if self._cache_timeout is not None:
                        pyfs = fs.remote.CacheFS(
                            pyfs, cache_timeout=self._cache_timeout)
                    url2_path, url2_filename = fs.path.split(url2)
                    if url2_path and not pyfs.exists(url2_path):
                        pyfs.makedir(url2_path, recursive=True)
                else:
                    # assume local filesystem
                    import fs.osfs
                    full_url = fs.opener._expand_syspath(self.filename)
                    url2_path, url2 = fs.path.split(full_url)
                    pyfs = fs.osfs.OSFS(url2_path)

                try:
                    # reuse the pyfilesystem and path
                    self._pyfs = pyfs
                    self._path = url2
                    return pyfs.open(url2, mode)
                except fs.errors.ResourceNotFoundError:
                    if writeable:
                        raise
                    else:
                        pass
            # NOTE: ignore read errors as the underlying caller can fail safely
            if writeable:
                raise
            else:
                pass
        return open_file

    @property
    def config(self):
        """load the passwords from the config file
        """
        if not hasattr(self, '_config'):
            raw_config = configparser.RawConfigParser()
            f = self._open()
            if f:
                raw_config.readfp(f)
                f.close()
            self._config = raw_config
        return self._config

    def get_password(self, service, username):
        """Read the password from the file.
        """
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # fetch the password
        try:
            password_base64 = self.config.get(service, username).encode()
            # decode with base64
            password_encrypted = base64.decodestring(password_base64)
            # decrypted the password
            password = self.decrypt(password_encrypted).decode('utf-8')
        except (configparser.NoOptionError, configparser.NoSectionError):
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password in the file.
        """
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # encrypt the password
        password = password or ''
        password_encrypted = self.encrypt(password.encode('utf-8'))

        # encode with base64
        password_base64 = base64.encodestring(password_encrypted).decode()
        # write the modification
        if not self.config.has_section(service):
            self.config.add_section(service)
        self.config.set(service, username, password_base64)
        config_file = self._open('w')
        self.config.write(config_file)
        config_file.close()

    def supported(self):
        """Applicable when Pyfilesystem installed, but do not recommend.
        """
        try:
            from fs.opener import fsopen
            return 0
        except ImportError:
            return -1

class UnencryptedPyfilesystemKeyring(BasicPyfilesystemKeyring):
    """Unencrypted Pyfilesystem Keyring
    """

    def __init__(self, filename=None, can_create=True, cache_timeout=None):
        super(UnencryptedPyfilesystemKeyring, self).__init__(
            NullCrypter(), filename=filename, can_create=can_create,
            cache_timeout=cache_timeout)

class EncryptedPyfilesystemKeyring(BasicPyfilesystemKeyring):
    """Encrypted Pyfilesystem Keyring
    """

    _filename = 'crypted_pyf_pass.cfg'

    def __init__(self, crypter, filename=None, can_create=True,
                 cache_timeout=None):
        super(EncryptedPyfilesystemKeyring, self).__init__(
            crypter, filename=filename, can_create=can_create,
            cache_timeout=cache_timeout)

class EnvironEncryptedPyfilesystemKeyring(EncryptedPyfilesystemKeyring):
    """Encrypted Pyfilesystem Keyring using Keyczar keysets specified in
    environment vars
    """

    def __init__(self):
        super(EnvironEncryptedPyfilesystemKeyring, self).__init__(
            EnvironKeyczarCrypter())

class MultipartKeyringWrapper(KeyringBackend):

    """A wrapper around an existing keyring that breaks the password into
    smaller parts to handle implementations that have limits on the maximum
    length of passwords i.e. Windows Vault
    """

    def __init__(self, keyring, max_password_size=512):
        self._keyring = keyring
        self._max_password_size = max_password_size

    def supported(self):
        """Return if this keyring supports current environment:
        -1: not applicable
         0: suitable
         1: recommended
        """
        return self._keyring.supported()

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        init_part = self._keyring.get_password(service, username)
        if init_part:
            parts = [init_part,]
            i = 1
            while True:
                next_part = self._keyring.get_password(
                    service,
                    '%s{{part_%d}}' %(username, i))
                if next_part:
                    parts.append(next_part)
                    i += 1
                else:
                    break
            return ''.join(parts)
        return None

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        password_parts = [
            password[i:i + self._max_password_size] for i in range(0,
                                                                   len(password),
                                                                   self._max_password_size)]
        for i, password_part in enumerate(password_parts):
            curr_username = username
            if i > 0:
                curr_username += '{{part_%d}}' %i
            self._keyring.set_password(service, curr_username, password_part)

@keyring.util.once
def get_all_keyring():
    """
    Return a list of all implemented keyrings.
    """
    return [
        keyring_class()
        for keyring_class in KeyringBackend._classes
    ]
