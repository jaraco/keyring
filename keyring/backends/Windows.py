import functools
import logging

from ..util import properties
from ..backend import KeyringBackend
from ..credentials import SimpleCredential
from ..errors import PasswordDeleteError, ExceptionRaisedContext

# NOTE: this can be increased
MAX_SHARDED_PASSWORD_LEN = 2 ** 16

MAX_SHARD_COUNT = MAX_SHARDED_PASSWORD_LEN // 1280 + 1
TARGET_SHARD = "{target}-shard-{i:04}"

with ExceptionRaisedContext() as missing_deps:
    try:
        # prefer pywin32-ctypes
        from win32ctypes.pywin32 import pywintypes
        from win32ctypes.pywin32 import win32cred

        # force demand import to raise ImportError
        win32cred.__name__
    except ImportError:
        # fallback to pywin32
        import pywintypes
        import win32cred

        # force demand import to raise ImportError
        win32cred.__name__

log = logging.getLogger(__name__)


class Persistence:
    def __get__(self, keyring, type=None):
        return getattr(keyring, '_persist', win32cred.CRED_PERSIST_ENTERPRISE)

    def __set__(self, keyring, value):
        """
        Set the persistence value on the Keyring. Value may be
        one of the win32cred.CRED_PERSIST_* constants or a
        string representing one of those constants. For example,
        'local machine' or 'session'.
        """
        if isinstance(value, str):
            attr = 'CRED_PERSIST_' + value.replace(' ', '_').upper()
            value = getattr(win32cred, attr)
        setattr(keyring, '_persist', value)


class DecodingCredential(dict):
    @property
    def value(self):
        """
        Attempt to decode the credential blob as UTF-16 then UTF-8.
        """
        cred = self['CredentialBlob']
        try:
            return cred.decode('utf-16')
        except UnicodeDecodeError:
            decoded_cred_utf8 = cred.decode('utf-8')
            log.warning(
                "Retrieved an UTF-8 encoded credential. Please be aware that "
                "this library only writes credentials in UTF-16."
            )
            return decoded_cred_utf8


class WinVaultKeyring(KeyringBackend):
    """
    WinVaultKeyring stores encrypted passwords using the Windows Credential
    Manager.

    Requires pywin32

    This backend does some gymnastics to simulate multi-user support,
    which WinVault doesn't support natively. See
    https://github.com/jaraco/keyring/issues/47#issuecomment-75763152
    for details on the implementation, but here's the gist:

    Passwords are stored under the service name unless there is a collision
    (another password with the same service name but different user name),
    in which case the previous password is moved into a compound name:
    {username}@{service}
    """

    persist = Persistence()

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        If available, the preferred backend on Windows.
        """
        if missing_deps:
            raise RuntimeError("Requires Windows and pywin32")
        return 5

    @staticmethod
    def _compound_name(username, service):
        return f'{username}@{service}'

    def _discover_max_password(self):
        def test_length(length):
            try:
                self._set_password("__probe_target__", "username", "a" * length)
                self._delete_password("__probe_target__")
                return True
            except Exception as e:
                if e.winerror == 1783 and e.funcname == 'CredWrite':
                    return False
                else:
                    raise

        start, end = 1, MAX_SHARDED_PASSWORD_LEN

        # initial guess assuming the max is 1280 to reduce search loops to 12 iterations
        mid = 1281
        while start <= end:
            if test_length(mid):
                start = mid + 1
            else:
                end = mid - 1
            mid = (start + end) // 2

        return end

    def __init__(self, *arg, **kw):
        super().__init__(*arg, **kw)

        self._max_password = 2 ** 32
        self._max_password = self._discover_max_password()

    def get_password(self, service, username):
        # first attempt to get the password under the service name
        res = self._get_password(service)
        if not res or res['UserName'] != username:
            # It wasn't found so attempt to get it with the compound name
            res = self._get_password(self._compound_name(username, service))
        if not res:
            return None
        return res.value

    def _get_password_inner(self, target):
        try:
            res = win32cred.CredRead(
                Type=win32cred.CRED_TYPE_GENERIC, TargetName=target
            )
        except pywintypes.error as e:
            e = OldPywinError.wrap(e)
            if e.winerror == 1168 and e.funcname == 'CredRead':  # not found
                return None
            raise

        return DecodingCredential(res)

    def _get_password(self, target):
        password = self._get_password_inner(target)

        if password:
            i = 1
            while True:
                shard = self._get_password_inner(TARGET_SHARD.format(target=target, i=i))
                if not shard:
                    return password
                else:
                    password["CredentialBlob"] += shard["CredentialBlob"]
                    i += 1
                    if i > MAX_SHARD_COUNT:
                        password_length = len(password["CredentialBlob"])
                        raise ValueError(f'_get_password: sharded {password_length=} exceeds {MAX_SHARD_COUNT=}')

    def set_password(self, service, username, password):
        existing_pw = self._get_password(service)
        if existing_pw:
            # resave the existing password using a compound target
            existing_username = existing_pw['UserName']
            target = self._compound_name(existing_username, service)
            self._set_password(
                target,
                existing_username,
                existing_pw.value,
            )
        self._set_password(service, username, str(password))

    def _set_password(self, target, username, password):
        password_len = len(password)
        if password_len > self._max_password:
            n = self._max_password
            max_shards = (password_len + n - 1) // n

            if max_shards > MAX_SHARD_COUNT:
                raise ValueError(f"_set_password: {password_len=} ({max_shards} shards) exceeds {MAX_SHARD_COUNT=}")

            # write all but the first shard
            for i in range(1, max_shards):
                shard = password[i * n: (i + 1) * n]
                credential = dict(
                    Type=win32cred.CRED_TYPE_GENERIC,
                    TargetName=TARGET_SHARD.format(target=target, i=i),
                    UserName=username,
                    CredentialBlob=shard,
                    Comment="Stored using python-keyring",
                    Persist=self.persist,
                )
                win32cred.CredWrite(credential, 0)
            # password set to first shard for "normal" writing
            password = password[0: n]

        credential = dict(
            Type=win32cred.CRED_TYPE_GENERIC,
            TargetName=target,
            UserName=username,
            CredentialBlob=password,
            Comment="Stored using python-keyring",
            Persist=self.persist,
        )
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

    def _delete_password_inner(self, target):
        try:
            win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)
            return True
        except pywintypes.error as e:
            e = OldPywinError.wrap(e)
            if e.winerror == 1168 and e.funcname == 'CredDelete':  # not found
                return
            raise

    def _delete_password(self, target):
        deleted = self._delete_password_inner(target)

        if deleted:
            i = 1
            while True:
                deleted = self._delete_password_inner(TARGET_SHARD.format(target=target, i=i))
                if not deleted:
                    return
                else:
                    i += 1
                    if i > MAX_SHARD_COUNT:
                        raise ValueError(f'_delete_password: exceeded {MAX_SHARD_COUNT=}')

    def get_credential(self, service, username):
        res = None
        # get the credentials associated with the provided username
        if username:
            res = self._get_password(self._compound_name(username, service))
        # get any first password under the service name
        if not res:
            res = self._get_password(service)
            if not res:
                return None
        return SimpleCredential(res['UserName'], res.value)


class OldPywinError:
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
