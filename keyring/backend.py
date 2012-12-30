"""
backend.py

Keyring Backend implementations
"""

from __future__ import with_statement

import os
import sys
import base64
import copy
import cPickle
import codecs

try:
    import io
except ImportError:
    # Support Python 2.4, 2.5
    import StringIO as io

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
    Return a list of all implemented keyrings that can be constructed without
    parameters.
    """
    return list(keyring.util.suppress_exceptions(KeyringBackend._classes,
        exceptions=TypeError))
