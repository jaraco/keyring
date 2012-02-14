"""
backend.py

Created by Kang Zhang on 2009-07-09
"""

import getpass
import os
import sys
import ConfigParser
import base64

from keyring.util.escape import escape as escape_for_ini
from keyring.util import properties
import keyring.util.platform
import keyring.util.loc_compat

try:
    from abc import ABCMeta, abstractmethod, abstractproperty
except ImportError:
    # to keep compatible with older Python versions.
    class ABCMeta(type):
        pass

    def abstractmethod(funcobj):
        return funcobj

    def abstractproperty(funcobj):
        return property(funcobj)

try:
    import gnomekeyring
except ImportError:
    pass

_KEYRING_SETTING = 'keyring-setting'
_CRYPTED_PASSWORD = 'crypted-password'
_BLOCK_SIZE = 32
_PADDING = '0'

class PasswordSetError(Exception):
    """Raised when the password can't be set.
    """

class KeyringBackend(object):
    """The abstract base class of the keyring, every backend must implement
    this interface.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def supported(self):
        """Return if this keyring supports current environment:
        -1: not applicable
         0: suitable
         1: recommended
        """
        return -1

    @abstractmethod
    def get_password(self, service, username):
        """Get password of the username for the service
        """
        return None

    @abstractmethod
    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        raise PasswordSetError("reason")

class _ExtensionKeyring(KeyringBackend):
    """_ExtensionKeyring is a adaptor class for the platform related keyring
    backends.
    """
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
        except OSError, e:
            raise PasswordSetError(e.message)

class OSXKeychain(_ExtensionKeyring):
    """Mac OS X Keychain"""
    def _init_backend(self):
        """Return the handler: osx_keychain
        """
        from backends import osx_keychain
        return osx_keychain

    def _recommend(self):
        """Recommended for all OSX environment.
        """
        return sys.platform == 'darwin'

class GnomeKeyring(KeyringBackend):
    """Gnome Keyring"""

    # Name of the keyring to store the passwords in.
    # Use None for the default keyring.
    KEYRING_NAME = None

    def supported(self):
        try:
            import gnomekeyring
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
        try:
            gnomekeyring.item_create_sync(
                self.KEYRING_NAME, gnomekeyring.ITEM_NETWORK_PASSWORD,
                "Password for '%s' on '%s'" % (username, service),
                {'user': username, 'domain': service},
                password, True)
        except gnomekeyring.CancelledError:
            # The user pressed "Cancel" when prompted to unlock their keyring.
            raise PasswordSetError("cancelled by user")

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
        if kwallet_support and os.environ.has_key('KDE_SESSION_UID'):
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
    """BasicFileKeyring is a file-based implementation of keyring.

    It stores the password directly in the file, and supports the
    encryption and decryption. The encrypted password is stored in base64
    format.
    """

    @properties.NonDataProperty
    def file_path(self):
        """
        The path to the file where passwords are stored. This property
        may be overridden by the subclass or at the instance level.
        """
        return os.path.join(keyring.util.platform.data_root(), self.filename)

    @abstractproperty
    def filename(self):
        """The filename used to store the passwords.
        """
        pass

    @abstractmethod
    def encrypt(self, password):
        """Encrypt the password.
        """
        pass

    @abstractmethod
    def decrypt(self, password_encrypted):
        """Decrypt the password.
        """
        pass

    def _relocate_file(self):
        old_location = os.path.join(os.path.expanduser('~'), self.filename)
        new_location = self.file_path
        keyring.util.loc_compat.relocate_file(old_location, new_location)
        # disable this function - it only needs to be run once
        self._relocate_file = lambda: None

    def get_password(self, service, username):
        """Read the password from the file.
        """
        self._relocate_file()
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # load the passwords from the file
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path):
            config.read(self.file_path)

        # fetch the password
        try:
            password_base64 = config.get(service, username).encode()
            # decode with base64
            password_encrypted = base64.decodestring(password_base64)
            # decrypted the password
            password = self.decrypt(password_encrypted).decode('utf-8')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password in the file.
        """
        self._relocate_file()
        service = escape_for_ini(service)
        username = escape_for_ini(username)

        # encrypt the password
        password_encrypted = self.encrypt(password.encode('utf-8'))
        # load the password from the disk
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path):
            config.read(self.file_path)

        # encode with base64
        password_base64 = base64.encodestring(password_encrypted).decode()
        # write the modification
        if not config.has_section(service):
            config.add_section(service)
        config.set(service, username, password_base64)
        # ensure the storage path exists
        if not os.path.isdir(os.path.dirname(self.file_path)):
            os.makedirs(os.path.dirname(self.file_path))
        config_file = open(self.file_path,'w')
        config.write(config_file)

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

    filename = 'crypted_pass.cfg'
    crypted_password = None

    def supported(self):
        """Applicable for all platforms, but not recommend"
        """
        try:
            from Crypto.Cipher import AES
            status = 0
        except ImportError:
            status = -1
        return status

    def _getpass(self, *args, **kwargs):
        """Wrap getpass.getpass(), so that we can override it when testing.
        """

        return getpass.getpass(*args, **kwargs)

    def _init_file(self):
        """Init the password file, set the password for it.
        """

        password = None
        while 1:
            if not password:
                password = self._getpass("Please set a password for your new keyring")
                password2 = self._getpass('Password (again): ')
                if password != password2:
                    sys.stderr.write("Error: Your passwords didn't match\n")
                    password = None
                    continue
            if '' == password.strip():
                # forbid the blank password
                sys.stderr.write("Error: blank passwords aren't allowed.\n")
                password = None
                continue
            if len(password) > _BLOCK_SIZE:
                # block size of AES is less than 32
                sys.stderr.write("Error: password can't be longer than 32.\n")
                password = None
                continue
            break

        # hash the password
        import crypt
        self.crypted_password = crypt.crypt(password, password)

        # write down the initialization
        config = ConfigParser.RawConfigParser()
        config.add_section(_KEYRING_SETTING)
        config.set(_KEYRING_SETTING, _CRYPTED_PASSWORD, self.crypted_password)

        config_file = open(self.file_path,'w')
        config.write(config_file)

        if config_file:
            config_file.close()

    def _check_file(self):
        """Check if the password file has been init properly.
        """
        if os.path.exists(self.file_path):
            config = ConfigParser.RawConfigParser()
            config.read(self.file_path)
            try:
                self.crypted_password = config.get(_KEYRING_SETTING,
                                                    _CRYPTED_PASSWORD)
                return self.crypted_password.strip() != ''
            except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                pass
        return False

    def _auth(self, password):
        """Return if the password can open the keyring.
        """
        import crypt
        return crypt.crypt(password, password) == self.crypted_password

    def _init_crypter(self):
        """Init the crypter(using the password of the keyring).
        """
        # check the password file
        if not self._check_file():
            self._init_file()

        password = self._getpass("Please input your password for the keyring")

        if not self._auth(password):
            sys.stderr.write("Wrong password for the keyring.\n")
            raise ValueError("Wrong password")

        # init the cipher with the password
        from Crypto.Cipher import AES
        # pad to _BLOCK_SIZE bytes
        password = password + (_BLOCK_SIZE - len(password) % _BLOCK_SIZE) * \
                                                                    _PADDING
        return AES.new(password, AES.MODE_CFB)

    def encrypt(self, password):
        """Encrypt the given password using the pycryto.
        """
        crypter = self._init_crypter()
        return crypter.encrypt(password)

    def decrypt(self, password_encrypted):
        """Decrypt the given password using the pycryto.
        """
        crypter = self._init_crypter()
        return crypter.decrypt(password_encrypted)


class Win32CryptoKeyring(BasicFileKeyring):
    """Win32 Cryptography Keyring"""

    filename = 'wincrypto_pass.cfg'

    def __init__(self):
        super(Win32CryptoKeyring, self).__init__()

        try:
            from backends import win32_crypto
            self.crypt_handler = win32_crypto
        except ImportError, e:
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
            import pywintypes, win32cred
            self.win32cred = win32cred
            self.pywintypes = pywintypes
        except ImportError:
            self.win32cred = None

    def supported(self):
        '''Default Windows backend, when it is available
        '''
        recommended = select_windows_backend()
        if recommended == None:
            return -1
        elif recommended == 'cred':
            return 1
        else:
            return 0

    @staticmethod
    def _compound_name(username, service):
        return u'%(username)s@%(service)s' % vars()

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
        except self.pywintypes.error, e:
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
            import _winreg
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
            password_encrypted = base64.encodestring(password_base64)
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
        import pywintypes, win32cred
        if (major, minor) >= (5, 1):
            # recommend for windows xp+
            return 'cred'
    except ImportError:
        pass
    try:
        from backends import win32_crypto
        import _winreg
        if (major, minor) >= (5, 0):
            # recommend for windows 2k+
            return 'reg'
    except ImportError:
        pass
    try:
        from backends import win32_crypto
        return 'file'
    except ImportError:
        pass
    return None


_all_keyring = None

def get_all_keyring():
    """Return the list of all keyrings in the lib
    """
    global _all_keyring
    if _all_keyring is None:
        _all_keyring = [ OSXKeychain(), GnomeKeyring(), KDEKWallet(),
                         CryptedFileKeyring(), UncryptedFileKeyring(),
                         Win32CryptoKeyring(), Win32CryptoRegistry(),
                         WinVaultKeyring()]
    return _all_keyring

