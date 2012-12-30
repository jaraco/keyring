"""
backend.py

Keyring Backend implementations
"""

from __future__ import with_statement

import os
import sys
import base64

import keyring.util.escape
from keyring.util import properties
import keyring.util.platform
import keyring.py25compat
try:
    from keyczar import keyczar
except ImportError:
    pass

# for backward-compatibility
from .errors import PasswordSetError, InitError

# use abstract base classes from the compat module
abc = keyring.py25compat.abc

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

# for backward-compatibility
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
    Return a list of all implemented keyrings that can be constructed without
    parameters.
    """
    return list(keyring.util.suppress_exceptions(KeyringBackend._classes,
        exceptions=TypeError))
