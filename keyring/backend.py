"""
Keyring implementation support
"""

import sys

from keyring.py25compat import abc
from keyring import errors

import keyring.util

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
        raise errors.PasswordSetError("reason")

    # for backward-compatibility, don't require a backend to implement
    #  delete_password
    #@abc.abstractmethod
    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        raise errors.PasswordDeleteError("reason")


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

@keyring.util.once
def get_all_keyring():
    """
    Return a list of all implemented keyrings that can be constructed without
    parameters.
    """
    return list(keyring.util.suppress_exceptions(KeyringBackend._classes,
        exceptions=TypeError))

# for backward-compatibility
from .errors import PasswordSetError, InitError
from keyring.backends.OS_X import Keyring as OSXKeychain
from keyring.backends.Gnome import Keyring as GnomeKeyring
from keyring.backends.SecretService import Keyring as SecretServiceKeyring
from keyring.backends.kwallet import Keyring as KDEKWallet
from keyring.backends.file import BaseKeyring as BasicFileKeyring
from keyring.backends.file import PlaintextKeyring as UncryptedFileKeyring
from keyring.backends.file import EncryptedKeyring as CryptedFileKeyring
from keyring.backends.Windows import EncryptedKeyring as Win32CryptoKeyring
from keyring.backends.Windows import WinVaultKeyring
from keyring.backends.Windows import RegistryKeyring as Win32CryptoRegistry
from keyring.backends.Windows import select_windows_backend
from keyring.backends.Google import DocsKeyring as GoogleDocsKeyring
from keyring.credentials import Credential
from keyring.credentials import SimpleCredential as BaseCredential
from keyring.credentials import EnvironCredential
from keyring.backends.Google import EnvironCredential as GoogleEnvironCredential
from keyring.backends.keyczar import BaseCrypter as BaseKeyczarCrypter
from keyring.backends.keyczar import Crypter as KeyczarCrypter
from keyring.backends.keyczar import EnvironCrypter as EnvironKeyczarCrypter
from keyring.backends.Google import KeyczarDocsKeyring as EnvironGoogleDocsKeyring
from keyring.backends.pyfs import BasicKeyring as BasicPyfilesystemKeyring
from keyring.backends.pyfs import PlaintextKeyring as UnencryptedPyfilesystemKeyring
from keyring.backends.pyfs import EncryptedKeyring as EncryptedPyfilesystemKeyring
from keyring.backends.pyfs import KeyczarKeyring as EnvironEncryptedPyfilesystemKeyring
from keyring.backends.multi import MultipartKeyringWrapper as MultipartKeyringWrapper
