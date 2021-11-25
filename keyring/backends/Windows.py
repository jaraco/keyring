import logging
import sys

from ..backend import KeyringBackend
from ..credentials import SimpleCredential
from ..errors import ExceptionRaisedContext, PasswordDeleteError
from ..util import properties

with ExceptionRaisedContext() as missing_deps:
    if sys.platform != 'win32':
        raise EnvironmentError(f'Windows backend requires sys.platform = \'win32\' but sys.platform={sys.platform}')
    else:
        from .windowsOS import api
        from .windowsOS.api import CredError


MAX_PASSWORD_BYTES = 2 ** 20
TARGET_SHARD = '{target}-shard-{n:04}'


log = logging.getLogger(__name__)


class Persistence:
    def __get__(self, keyring, type=None):
        return getattr(keyring, '_persist', api.CRED_PERSIST_ENTERPRISE)

    def __set__(self, keyring, value):
        """
        Set the persistence value on the Keyring. Value may be
        one of the CRED_PERSIST_* constants or a
        string representing one of those constants. For example,
        'local machine' or 'session'.
        """
        if isinstance(value, str):
            attr = 'CRED_PERSIST_' + value.replace(' ', '_').upper()
            value = getattr(api, attr, api.CRED_PERSIST_ENTERPRISE)
        setattr(keyring, '_persist', value)


class DecodingCredential(dict):
    @property
    def value(self):
        """
        Attempt to decode the credential blob as UTF-16 then UTF-8.
        """
        cred = self['CredentialBlob']

        # NOTE if we have our metadata, we know how to decode
        if api.ATTRIBUTE_KEYWORD in self:
            return cred.decode(self[api.ATTRIBUTE_KEYWORD]['encoding'])

        try:
            return cred.decode('utf-16')
        except UnicodeDecodeError:
            decoded_cred_utf8 = cred.decode('utf-8')
            log.warning(
                "Retrieved an UTF-8 encoded credential not created by keyring."
            )
            return decoded_cred_utf8


class WinVaultKeyring(KeyringBackend):
    """
    WinVaultKeyring stores encrypted passwords using the Windows Credential
    Manager.

    Requires cffi

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
            raise RuntimeError("Requires Windows and cffi")
        return 5

    @staticmethod
    def _compound_name(username, service):
        return f'{username}@{service}'

    def _discover_max_password_bytes(self):
        """
        Test 2560 bytes as max. If it isn't, use binary
        search to discover actual max password on this
        instance of Windows.
        """
        def test_length(length):
            try:
                try:
                    self._discovery_probe_password('__probe_target__', 'a' * length)
                except Exception as e:
                    if not (isinstance(e, CredError) and e.winerror == 1783):
                        log.exception(f"_set_password raised e={e}")
                    raise
                self._delete_password_inner('__probe_target__')
                return True
            except CredError as e:
                if e.winerror == 1783 and e.funcname == 'CredWrite':
                    return False
                else:
                    log.exception('unexpected CredError')
                    return False
            except Exception:
                log.exception('unexpected Exception')

        # first try to confirm max bytes of 2560
        if test_length(2560) and not test_length(2561):
            return 2560

        # otherwise, use binary search
        start, end = 1, MAX_PASSWORD_BYTES
        while start <= end:
            mid = (start + end) // 2
            if test_length(mid):
                start = mid + 1
            else:
                end = mid - 1
        return end

    def __init__(self, *arg, **kw):
        super().__init__(*arg, **kw)

        self._max_password_bytes = self._discover_max_password_bytes()

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
            res = api.CredRead(Type=api.CRED_TYPE_GENERIC, TargetName=target)
        except CredError as e:
            if e.winerror == 1168 and e.funcname == 'CredRead':  # not found
                return None
            raise
        return DecodingCredential(res)

    def _get_password(self, target):
        creds = self._get_password_inner(target)
        if creds and api.ATTRIBUTE_KEYWORD in creds and creds[api.ATTRIBUTE_KEYWORD]['max_shards'] > 1:
            for i in range(1, creds[api.ATTRIBUTE_KEYWORD]['max_shards']):
                shard = self._get_password_inner(TARGET_SHARD.format(target=target, n=i))
                if not shard:
                    log.critical(f'expected shard {i} not found; {creds[api.ATTRIBUTE_KEYWORD]}')
                    return creds
                else:
                    creds['CredentialBlob'] += shard['CredentialBlob']
        return creds

    def set_password(self, service, username, password):
        existing_pw = self._get_password(service)
        if existing_pw:
            existing_username = existing_pw['UserName']
            if existing_username != username:
                # resave the existing password using a compound target
                # only if this call is for a different user name than the existing one
                target = self._compound_name(existing_username, service)
                self._set_password(target, existing_username, existing_pw.value)
        self._set_password(service, username, str(password))

    def _set_password(self, target, username, password):
        encoding = 'utf-16'
        pwd_bytes = password.encode(encoding)
        pwd_len = len(pwd_bytes)
        if pwd_len > self._max_password_bytes:
            # the utf-16 encoded password won't fit in a single record,
            # so try utf-8, sharding if necessary
            encoding = 'utf-8'
            pwd_bytes = password.encode(encoding)
            pwd_len = len(pwd_bytes)

        if pwd_len > MAX_PASSWORD_BYTES:
            raise ValueError(MAX_PASSWORD_BYTES, '_set_password: pwd_len={pwd_len} exceeds {MAX_PASSWORD_BYTES}')

        n = self._max_password_bytes
        max_shards = max((pwd_len + n - 1) // n, 1)

        for i in range(0, max_shards):
            shard = pwd_bytes[i * n: (i + 1) * n]

            credential = dict(
                Type=api.CRED_TYPE_GENERIC,
                TargetName=TARGET_SHARD.format(target=target, n=i) if i else target,
                UserName=username,
                CredentialBlob=shard,
                Comment='Stored using python-keyring',
                Persist=self.persist,
                _shard_num=i,
                _max_shards=max_shards,
                encoding=encoding
            )
            api.CredWrite(credential, 0)

    def _discovery_probe_password(self, target, password):
        pwd_utf8_bytes = password.encode('utf-8')

        credential = dict(
            Type=api.CRED_TYPE_GENERIC,
            TargetName=target,
            UserName='username',
            CredentialBlob=pwd_utf8_bytes,
            Comment='Stored using python-keyring',
            Persist=self.persist,
            _shard_num=0,
            _max_shards=1,
            encoding='utf-8'
        )
        api.CredWrite(credential, 0)

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
            api.CredDelete(Type=api.CRED_TYPE_GENERIC, TargetName=target)
            return True
        except CredError as e:
            if e.winerror == 1168 and e.funcname == 'CredDelete':  # not found
                return
            raise

    def _delete_password(self, target):
        if self._delete_password_inner(target):
            for i in range(1, MAX_PASSWORD_BYTES // self._max_password_bytes):
                deleted = self._delete_password_inner(TARGET_SHARD.format(target=target, n=i))
                if not deleted:
                    break

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
