from __future__ import unicode_literals

import functools

from ..py27compat import text_type
from ..util import properties
from ..backend import KeyringBackend
from ..errors import PasswordDeleteError, ExceptionRaisedContext

try:
    # prefer pywin32-ctypes
    from win32ctypes import pywintypes
    from win32ctypes import win32cred
    # force demand import to raise ImportError
    win32cred.__name__
except ImportError:
    # fallback to pywin32
    try:
        import pywintypes
        import win32cred
    except ImportError:
        pass


def has_pywin32():
    """
    Does this environment have pywin32?
    Should return False even when Mercurial's Demand Import allowed import of
    win32cred.
    """
    with ExceptionRaisedContext() as exc:
        win32cred.__name__
    return not bool(exc)


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

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        If available, the preferred backend on Windows.
        """
        if not has_pywin32():
            raise RuntimeError("Requires Windows and pywin32")
        return 5

    @staticmethod
    def _compound_name(username, service):
        return '%(username)s@%(service)s' % vars()

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
            res = win32cred.CredRead(
                Type=win32cred.CRED_TYPE_GENERIC,
                TargetName=target,
            )
        except pywintypes.error as e:
            e = OldPywinError.wrap(e)
            if e.winerror == 1168 and e.funcname == 'CredRead':  # not found
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
        self._set_password(service, username, text_type(password))

    def _set_password(self, target, username, password):
        credential = dict(Type=win32cred.CRED_TYPE_GENERIC,
                          TargetName=target,
                          UserName=username,
                          CredentialBlob=password,
                          Comment="Stored using python-keyring",
                          Persist=win32cred.CRED_PERSIST_ENTERPRISE)
        win32cred.CredWrite(credential, 0)

    def delete_password(self, service, username):
        compound = self._compound_name(username, service)
        deleted = False
        for target in service, compound:
            existing_pw = self._get_password(target)
            if existing_pw and existing_pw['UserName'] == username:
                deleted = True
                self._delete_password(target)
        if not deleted:
            raise PasswordDeleteError(service)

    def _delete_password(self, target):
        win32cred.CredDelete(
            Type=win32cred.CRED_TYPE_GENERIC,
            TargetName=target,
        )


class OldPywinError(object):
    """
    A compatibility wrapper for old PyWin32 errors, such as reported in
    https://bitbucket.org/kang/python-keyring-lib/issue/140/
    """

    def __init__(self, orig):
        self.orig = orig

    @property
    def funcname(self):
        return self.orig[1]

    @property
    def winerror(self):
        return self.orig[0]

    @classmethod
    def wrap(cls, orig_err):
        attr_check = functools.partial(hasattr, orig_err)
        is_old = not all(map(attr_check, ['funcname', 'winerror']))
        return cls(orig_err) if is_old else orig_err
