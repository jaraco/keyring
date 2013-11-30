from __future__ import with_statement

import os
import getpass
import base64
import sys
import json
import abc

from ..py27compat import configparser

import keyring.util.platform_
from keyring.errors import PasswordDeleteError
from keyring.backend import KeyringBackend
from keyring.util import properties
from keyring.util.escape import escape as escape_for_ini


class FileBacked(object):
    @abc.abstractproperty
    def filename(self):
        """
        The filename used to store the passwords.
        """

    @properties.NonDataProperty
    def file_path(self):
        """
        The path to the file where passwords are stored. This property
        may be overridden by the subclass or at the instance level.
        """
        return os.path.join(keyring.util.platform_.data_root(), self.filename)


class BaseKeyring(FileBacked, KeyringBackend):
    """
    BaseKeyring is a file-based implementation of keyring.

    This keyring stores the password directly in the file and provides methods
    which may be overridden by subclasses to support
    encryption and decryption. The encrypted payload is stored in base64
    format.
    """

    @abc.abstractmethod
    def encrypt(self, password):
        """
        Given a password (byte string), return an encrypted byte string.
        """

    @abc.abstractmethod
    def decrypt(self, password_encrypted):
        """
        Given a password encrypted by a previous call to `encrypt`, return
        the original byte string.
        """

    def get_password(self, service, username):
        """
        Read the password from the file.
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
        with open(self.file_path, 'w') as config_file:
            config.write(config_file)

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
            user_read_write = 0o600
            os.chmod(self.file_path, user_read_write)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        service = escape_for_ini(service)
        username = escape_for_ini(username)
        config = configparser.RawConfigParser()
        if os.path.exists(self.file_path):
            config.read(self.file_path)
        try:
            if not config.remove_option(service, username):
                raise PasswordDeleteError("Password not found")
        except configparser.NoSectionError:
            raise PasswordDeleteError("Password not found")
        # update the file
        with open(self.file_path, 'w') as config_file:
            config.write(config_file)

class PlaintextKeyring(BaseKeyring):
    """Simple File Keyring with no encryption"""

    priority = .5
    "Applicable for all platforms, but not recommended"

    filename = 'keyring_pass.cfg'

    def encrypt(self, password):
        """Directly return the password itself.
        """
        return password

    def decrypt(self, password_encrypted):
        """Directly return encrypted password.
        """
        return password_encrypted

class Encrypted(object):
    """
    PyCrypto-backed Encryption support
    """

    block_size = 32

    def _create_cipher(self, password, salt, IV):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Cipher import AES
        pw = PBKDF2(password, salt, dkLen=self.block_size)
        return AES.new(pw[:self.block_size], AES.MODE_CFB, IV)

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


class EncryptedKeyring(Encrypted, BaseKeyring):
    """PyCrypto File Keyring"""

    filename = 'crypted_pass.cfg'
    pw_prefix = 'pw:'.encode()

    @properties.ClassProperty
    @classmethod
    def priority(self):
        "Applicable for all platforms, but not recommended."
        try:
            __import__('Crypto.Cipher.AES')
            __import__('Crypto.Protocol.KDF')
            __import__('Crypto.Random')
        except ImportError:
            raise RuntimeError("PyCrypto required")
        if not json:
            raise RuntimeError("JSON implementation such as simplejson "
                "required.")
        return .6

    @properties.NonDataProperty
    def keyring_key(self):
        # _unlock or _init_file will set the key or raise an exception
        if self._check_file():
            self._unlock()
        else:
            self._init_file()
        return self.keyring_key

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

    def encrypt(self, password):
        from Crypto.Random import get_random_bytes
        salt = get_random_bytes(self.block_size)
        from Crypto.Cipher import AES
        IV = get_random_bytes(AES.block_size)
        cipher = self._create_cipher(self.keyring_key, salt, IV)
        password_encrypted = cipher.encrypt(self.pw_prefix + password)
        # Serialize the salt, IV, and encrypted password in a secure format
        data = dict(
            salt=salt, IV=IV, password_encrypted=password_encrypted,
        )
        for key in data:
            data[key] = base64.encodestring(data[key]).decode()
        return json.dumps(data).encode()

    def decrypt(self, password_encrypted):
        # unpack the encrypted payload
        data = json.loads(password_encrypted.decode())
        for key in data:
            data[key] = base64.decodestring(data[key].encode())
        cipher = self._create_cipher(self.keyring_key, data['salt'],
            data['IV'])
        plaintext = cipher.decrypt(data['password_encrypted'])
        assert plaintext.startswith(self.pw_prefix)
        return plaintext[3:]

    def _migrate(self, keyring_password=None):
        """
        Convert older keyrings to the current format.
        """


import contextlib
import copy

class EncryptedKeyringEx(Encrypted, FileBacked, KeyringBackend):
    filename = 'crypted keyring.json'
    iteration_count = 2000

    @properties.ClassProperty
    @classmethod
    def priority(self):
        "Applicable for all platforms, but not recommended."
        try:
            __import__('Crypto.Cipher.AES')
            __import__('Crypto.Protocol.KDF')
            __import__('Crypto.Random')
        except ImportError:
            raise RuntimeError("PyCrypto required")
        if not json:
            raise RuntimeError("JSON implementation such as simplejson "
                "required.")
        return -1 # disabled

    def get_password(self, service, username):
        with self.get_entries() as entries:
            return entries[service][username]

    def set_password(self, service, username, password):
        with self.get_entries() as entries:
            service = entries.setdefault(service, {})
            service[username] = password

    @contextlib.contextmanager
    def get_entries(self):
        """
        Yield the decrypted entries and re-write any changes.
        """
        self._unlock()
        with self.get_data() as data:
            cipher_info = data['cipher']
            entries = self._decrypt_json(cipher_info, data.get('entries')) or {}
            yield entries
            data['entries'] = self._encrypt_json(entries)

    def _decrypt_json(self, cipher_info, payload):
        """
        Decrypt an encrypted payload that's expected to be JSON.
        """
        if payload is None:
            return

        cipher = self._create_cipher(self.master_key,
            cipher_info['salt'], cipher_info['initialization_vector'])

        cipher_text = base64.decodestring(payload)
        plain_text = cipher.decrypt(cipher_text)
        return json.loads(plain_text)

    def _encrypt_json(self, cipher_info, doc):
        """
        Encrypt a JSON document as a base64-encoded payload.
        """
        cipher = self._create_cipher(self.master_key,
            cipher_info['salt'], cipher_info['initialization_vector'])

        plain_text = json.dumps(doc)
        cipher_text = cipher.encrypt(plain_text)
        return base64.encodestring(cipher_text)

    def _generate_key(self, password):
        from Crypto.Random import get_random_bytes
        from Crypto.Cipher import AES
        salt = get_random_bytes(self.block_size)
        master_key = self._PBKDF2_SHA256(salt, password, self.iteration_count)
        verification_value = self._SHA256("V:" + self.master_key)
        initialization_vector = get_random_bytes(AES.block_size)
        cipher_info = dict(
            salt=salt,
            iteration_count=self.iteration_count,
            verification_value=verification_value,
            initialization_vector=initialization_vector,
        )
        return master_key, cipher_info

    def _verify_password(self, password, info):
        master_key = self._PBKDF2_SHA256(info['salt'], password, info['iteration_count'])
        candidate_verification = self._SHA256("V:" + master_key)
        if candidate_verification != info['verification_value']:
            raise Exception("Incorrect Password")
        return master_key

    def _init_file(self):
        master_pass = self._get_new_password()
        self.master_key, cipher_info = self._generate_key(master_pass)
        with self.get_data() as data:
            data.update(
                version=1,
                cipher=cipher_info,
            )

    @contextlib.contextmanager
    def get_data(self):
        """
        Open the datafile, yield its decoded contents, and then re-save the
        contents if the result has changed.

        # TODO: open the file only once with exclusive perms
        """
        data = {}
        if os.path.exists(self.file_path):
            with open(self.file_path) as f:
                data = json.load(f)
        orig_data = copy.deepcopy(data)
        try:
            yield data
        finally:
            if data != orig_data:
                with open(self.file_path, 'w') as f:
                    json.dump(f, data)

    def _unlock(self):
        """
        Unlock this keyring by getting the password for the keyring from the
        user.
        """
        master_pass = getpass.getpass(
            'Please enter password for encrypted keyring: ')
        with self.get_data() as data:
            assert data['version'] == 1, "Unsupported version"
            self.master_key = self._verify_password(master_pass, data['cipher'])

    def _lock(self):
        """
        Remove the keyring key from this instance.
        """
        del self.master_key
