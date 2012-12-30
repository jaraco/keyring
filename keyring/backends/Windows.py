import os
import sys
import base64

import keyring.util.escape
from keyring.backend import KeyringBackend
from . import file

class EncryptedKeyring(file.BaseKeyring):
    """
    A File-based keyring secured by Windows Crypto API.
    """

    filename = 'wincrypto_pass.cfg'

    def __init__(self):
        super(EncryptedKeyring, self).__init__()

        try:
            from . import _win_crypto
            self.crypt_handler = _win_crypto
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


class RegistryKeyring(KeyringBackend):
    """RegistryKeyring is a keyring which use Windows CryptAPI to encrypt
    the user's passwords and store them under registry keys
    """
    def __init__(self):
        super(RegistryKeyring, self).__init__()

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
