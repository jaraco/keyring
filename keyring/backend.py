"""
Keyring implementation support
"""

import itertools

from keyring.py25compat import abc
from keyring import errors
from keyring.util import properties

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

    #@abc.abstractproperty
    def priority(cls):
        """
        Each backend class must supply a priority, a number (float or integer)
        indicating the priority of the backend relative to all other backends.
        The priority need not be static -- it may (and should) vary based
        attributes of the environment in which is runs (platform, available
        packages, etc.).

        A higher number indicates a higher priority. The priority should raise
        a RuntimeError with a message indicating the underlying cause if the
        backend is not suitable for the current environment.

        As a rule of thumb, a priority between zero but less than one is
        suitable, but a priority of one or greater is recommended.
        """

    @properties.ClassProperty
    @classmethod
    def viable(cls):
        with errors.ExceptionRaisedContext() as exc:
            cls.priority
        return not bool(exc)

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
    def is_class_viable(keyring_cls):
        try:
            keyring_cls.priority
        except RuntimeError:
            return False
        return True

    all_classes = KeyringBackend._classes
    viable_classes = itertools.ifilter(is_class_viable, all_classes)
    return list(keyring.util.suppress_exceptions(viable_classes,
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
