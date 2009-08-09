"""
backend.py

Created by Kang Zhang on 2009-07-09
"""

import os
import sys
import crypt
import getpass
import ConfigParser

from abc import ABCMeta, abstractmethod

_KEYRING_SETTING = 'keyring-setting'
_CRYPTED_PASSWORD = 'crypted-password'
_BLOCK_SIZE = 32
_PADDING = '0'

class KeyringBackend():
    """The abstract base class of the keyring, every backend must implement
    this interface.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def supported(self):
        """Return if this keyring supports current enviroment.
        -1: not applicable
         0: suitable
         1: recommended
        """
        return -1

    @abstractmethod
    def get_password(self, service, username): 
        """Get password of the username for the service
        """
        pass

    @abstractmethod
    def set_password(self, service, username, password): 
        """Set password for the username of the service
        """
        return -1

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
        """If this keyring is recommanded on current enviroment.
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
        return self.keyring_impl.password_get(service, username)

    def set_password(self, service, username, password):
        """Overide the set_password() in KeyringBackend.
        """
        return self.keyring_impl.password_set(service, username, password)
 
class OSXKeychain(_ExtensionKeyring):
    """The keyring backend based on Keychain Service of the Mac OSX
    """
    def _init_backend(self):
        """Return the handler: osx_keychain
        """
        import osx_keychain
        return osx_keychain

    def _recommend(self):
        """Recommend for all OSX enviroment.
        """
        return sys.platform in ['darwin', 'mac'] 

class GnomeKeyring(_ExtensionKeyring):
    """The keyring backend using Gnome Keyring.
    """
    def _init_backend(self):
        """Return the gnome_keyring handler.
        """
        import gnome_keyring
        return gnome_keyring

    def _recommend(self):
        """Recommend this keyring when Gnome is running.
        """
        # Gnome is running 
        return os.getenv("GNOME_DESKTOP_SESSION_ID") is not None

      
class KDEKWallet(_ExtensionKeyring):
    """The keyring backend based on KDE KWallet
    """
    def _init_backend(self):
        """Return the kde_kwallet handler.
        """
        import kde_kwallet
        return kde_kwallet
 
    def _recommend(self):
        """Recommend this keyring backend when KDE is running.
        """
        # KDE is running 
        return os.getenv("KDE_FULL_SESSION") == "true"

class BasicFileKeyring(KeyringBackend):
    """BasicFileKeyring is a filebased implementation of keyring. It store the 
    password directly in the file, and supports the encryption and decryption.
    The encrypted password is stroed in base64 format.
    """

    def __init__(self):
        self.file_path = os.path.join(os.path.expanduser("~"), self.filename())
    
    @abstractmethod
    def filename(self):
        """Return the filename used to store the passwords.
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

    def get_password(self, service, username):
        """Read the password from the file.
        """
        # load the passwords from the file
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path): 
            config.read(self.file_path)

        # fetch the password
        try:
            password_base64 = config.get(service, username)
            # decode with base64
            password_encrypted = password_base64.decode("base64")
            # decrypted the password
            password = self.decrypt(password_encrypted)
        except ConfigParser.NoOptionError: 
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password in the file.
        """
        # encrypt the password 
        password_encrypted = self.encrypt(password)
        # load the password from the disk
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path): 
            config.read(self.file_path)

        # encode with base64
        password_base64 = password_encrypted.encode("base64")
        # write the modification
        if not config.has_section(service):
            config.add_section(service)
        config.set(service, username, password_base64)
        config_file = open(self.file_path,'w')
        config.write(config_file)
        if config_file: 
            config_file.close()

        return 0

class UncryptedFileKeyring(BasicFileKeyring):
    """A simple filekeyring which dose not encrypt the password.
    """
    def filename(self):
        """Return the filename of the password file. It should be
        "keyring_pass.cfg" .
        """
        return "keyring_pass.cfg"

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
    """CryptedFileKeyring is a keyring using lib pycryto to encrypt the password
    """
    def __init__(self):
        super(CryptedFileKeyring, self).__init__()

        self.crypted_password = None
        
    def filename(self):
        """Return the filename for the password file.
        """
        return "crypted_pass.cfg"

    def supported(self):
        """Applicable for all platforms, but not recommend"
        """
        try:
            from Crypto.Cipher import AES
            status = 0
        except ImportError:
            status = -1
        return status

    def _init_file(self):
        """Init the password file, set the password for it.
        """

        print "Please set a password for your new keyring"
        password = None
        while 1:
            if not password:
                password = getpass.getpass()
                password2 = getpass.getpass('Password (again): ')
                if password != password2:
                    sys.stderr.write("Error: Your passwords didn't math\n")
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
        return crypt.crypt(password, password) == self.crypted_password

    def _init_crypter(self):
        """Init the crypter(using the password of the keyring).
        """
        # check the password file
        if not self._check_file():
            self._init_file()

        print "Please input your password for the keyring"
        password = getpass.getpass()

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
    """Win32CryptoKeyring is a keyring which use Windows CryptAPI to encrypt
    the user's passwords and store them in a file.
    """
    def __init__(self):
        super(Win32CryptoKeyring, self).__init__()

        try:
            import win32_crypto
            self.crypt_handler = win32_crypto
        except ImportError: 
            self.crypt_handler = None

    def filename(self):
        """Return the filename for the password storages file.
        """
        return "wincrypto_pass.cfg"

    def supported(self):
        """Recommend for all Windows is higher than Windows 2000.
        """
        if self.crypt_handler is not None and sys.platform in ['win32']:
            major, minor, build, platform, text = sys.getwindowsversion()
            if platform == 2:
                # recommend for windows 2k+ 
                return 1
        return -1

    def encrypt(self, password):
        """Encrypt the password using the CryptAPI.
        """
        return self.crypt_handler.encrypt(password)

    def decrypt(self, password_encrypted):
        """Decrypt the password using the CryptAPI.
        """
        return self.crypt_handler.decrypt(password_encrypted)


_all_keyring = None

def get_all_keyring():
    """Return the list of all keyrings in the lib
    """
    global _all_keyring
    if _all_keyring is None:
        _all_keyring = [ OSXKeychain(), GnomeKeyring(), KDEKWallet(), 
                            CryptedFileKeyring(), UncryptedFileKeyring(), 
                            Win32CryptoKeyring()]
    return _all_keyring

