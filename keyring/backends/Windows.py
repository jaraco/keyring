import json
import logging
import sys
from weakref import WeakKeyDictionary

from ..backend import KeyringBackend
from ..credentials import SimpleCredential
from ..errors import ExceptionRaisedContext, PasswordDeleteError
from ..util import properties

MAX_PASSWORD_BYTES = 2 ** 20
TARGET_SHARD = "{target}-shard-{n:04}"
ATTRIBUTE_KEYWORD = "keyring_metadata"


# region standalone replacement for win32cred
with ExceptionRaisedContext() as missing_deps:
    import cffi

    if sys.platform != "win32":
        raise EnvironmentError(f"Windows backend requires sys.platform = 'win32' but {sys.platform=}")


ffi = cffi.FFI()

ffi.set_unicode(True)

advapi32 = ffi.dlopen("advapi32.dll")

ffi.cdef("""

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct _CREDENTIAL_ATTRIBUTE {
  LPWSTR Keyword;
  DWORD  Flags;
  DWORD  ValueSize;
  LPBYTE Value;
} CREDENTIAL_ATTRIBUTE, *PCREDENTIAL_ATTRIBUTE;

typedef struct _CREDENTIAL {
  DWORD                 Flags;
  DWORD                 Type;
  LPWSTR                TargetName;
  LPWSTR                Comment;
  FILETIME              LastWritten;
  DWORD                 CredentialBlobSize;
  LPBYTE                CredentialBlob;
  DWORD                 Persist;
  DWORD                 AttributeCount;
  PCREDENTIAL_ATTRIBUTE Attributes;
  LPWSTR                TargetAlias;
  LPWSTR                UserName;
} CREDENTIAL, *PCREDENTIAL;


BOOL WINAPI CredReadW(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIAL *Credential);
BOOL WINAPI CredWriteW(PCREDENTIAL Credential, DWORD);
VOID WINAPI CredFree(PVOID Buffer);
BOOL WINAPI CredDeleteW(LPCWSTR TargetName, DWORD Type, DWORD Flags);

""")

CRED_TYPE_GENERIC = 0x1
CRED_PERSIST_SESSION = 0x1
CRED_PERSIST_LOCAL_MACHINE = 0x2
CRED_PERSIST_ENTERPRISE = 0x3
CRED_PRESERVE_CREDENTIAL_BLOB = 0

SUPPORTED_CREDKEYS = set((
    "Type", "TargetName", "Persist",
    "UserName", "Comment", "CredentialBlob"))


class CredError(Exception):
    def __init__(self, *args, **kw):
        nargs = len(args)
        if nargs > 0:
            self.winerror = args[0]
        else:
            self.winerror = None
        if nargs > 1:
            self.funcname = args[1]
        else:
            self.funcname = None
        if nargs > 2:
            self.strerror = args[2]
        else:
            self.strerror = None
        Exception.__init__(self, *args, **kw)


def _raise_error(function_name=""):
    code, message = ffi.getwinerror()
    raise CredError(code, function_name, message)


def PCREDENTIAL_ATTRIBUTE(value=None):
    return ffi.new("PCREDENTIAL_ATTRIBUTE", ffi.NULL if value is None else value)


def PPCREDENTIAL_ATTRIBUTE(value=None):
    return ffi.new("PCREDENTIAL_ATTRIBUTE*", ffi.NULL if value is None else value)


def PCREDENTIAL(value=None):
    return ffi.new("PCREDENTIAL", ffi.NULL if value is None else value)


def PPCREDENTIAL(value=None):
    return ffi.new("PCREDENTIAL*", ffi.NULL if value is None else value)


_keep_alive = WeakKeyDictionary()


def credential_from_dict(credential, flag=0):
    if flag != 0:
        raise ValueError("flag != 0 not yet supported")

    # region Attributes
    c_attrs = ffi.new("PCREDENTIAL_ATTRIBUTE")[0]
    # values to ref and make sure that they will not go away
    values = []

    value = ffi.new("wchar_t[]", ATTRIBUTE_KEYWORD)
    values.append(value)
    c_attrs.Keyword = ffi.cast("LPTSTR", value)

    c_attrs.Flags = 0

    metadata = json.dumps(
        dict(
            max_shards=credential["_max_shards"],
            shard_num=credential["_shard_num"],
            encoding="utf-8"
        )
    )
    metadata_bytes = metadata.encode("utf-8")
    value = ffi.new("BYTE[]", metadata_bytes)
    values.append(value)
    # new adds a NULL at the end that we do not want.
    c_attrs.ValueSize = ffi.sizeof(value) - ffi.sizeof("char")
    c_attrs.Value = ffi.cast("LPBYTE", value)

    # keep values alive until c_attrs goes away.
    _keep_alive[c_attrs] = tuple(values)
    # endregion

    c_creds = ffi.new("PCREDENTIAL")[0]
    # values to ref and make sure that they will not go away
    values = []
    for key in SUPPORTED_CREDKEYS:
        if key in credential:
            if key == "CredentialBlob":
                blob = credential["CredentialBlob"]
                blob_data = ffi.new("BYTE[]", blob)
                values.append(blob_data)
                # new adds a NULL at the end that we do not want.
                c_creds.CredentialBlobSize = ffi.sizeof(blob_data) - ffi.sizeof("char")
                c_creds.CredentialBlob = ffi.cast("LPBYTE", blob_data)
            elif key in ("Type", "Persist"):
                setattr(c_creds, key, credential[key])
            else:
                blob = credential[key]
                value = ffi.new("wchar_t[]", blob)
                values.append(value)
                setattr(c_creds, key, ffi.cast("LPTSTR", value))

    c_creds.AttributeCount = 1
    c_creds.Attributes = PCREDENTIAL_ATTRIBUTE(c_attrs)
    values.append(c_attrs)

    # keep values alive until c_creds goes away.
    _keep_alive[c_creds] = tuple(values)
    return c_creds


def credential_to_dict(pc_creds):
    credentials = {}
    for key in SUPPORTED_CREDKEYS:
        if key == "CredentialBlob":
            data = ffi.buffer(pc_creds.CredentialBlob, pc_creds.CredentialBlobSize)[:]  # [:] causes copy
        elif key in ("Type", "Persist"):
            data = int(getattr(pc_creds, key))
        else:
            string_pointer = getattr(pc_creds, key)
            if string_pointer == ffi.NULL:
                data = ""
            else:
                data = ffi.string(string_pointer)
        credentials[key] = data

    if hasattr(pc_creds, "AttributeCount") and hasattr(pc_creds, "Attributes"):
        credentials["AttributeCount"] = int(pc_creds.AttributeCount)
        if pc_creds.AttributeCount == 1 and ffi.string(pc_creds.Attributes.Keyword) == ATTRIBUTE_KEYWORD:
            metadata_bytes = ffi.buffer(pc_creds.Attributes.Value, pc_creds.Attributes.ValueSize)[:]
            metadata_string = metadata_bytes.decode("utf-8")
            credentials[ATTRIBUTE_KEYWORD] = json.loads(metadata_string)

    return credentials


def CredWrite(Credential, Flags=CRED_PRESERVE_CREDENTIAL_BLOB):
    c_creds = credential_from_dict(Credential, Flags)
    c_pcreds = PCREDENTIAL(c_creds)
    if advapi32.CredWriteW(c_pcreds, Flags) == 0:
        _raise_error("CredWrite")


def CredRead(TargetName, Type, Flags=0):
    flag = 0
    ppcreds = PPCREDENTIAL()
    if advapi32.CredReadW(TargetName, Type, flag, ppcreds) == 0:
        _raise_error("CredRead")
    pcreds = ppcreds[0]

    try:
        res = credential_to_dict(pcreds[0])
    finally:
        advapi32.CredFree(pcreds)

    return res


def CredDelete(TargetName, Type, Flags=0):
    if advapi32.CredDeleteW(TargetName, Type, Flags) == 0:
        _raise_error("CredDelete")
# endregion


log = logging.getLogger(__name__)


class Persistence:
    def __get__(self, keyring, type=None):
        return getattr(keyring, "_persist", CRED_PERSIST_ENTERPRISE)

    def __set__(self, keyring, value):
        """
        Set the persistence value on the Keyring. Value may be
        one of the CRED_PERSIST_* constants or a
        string representing one of those constants. For example,
        "local machine" or "session".
        """
        if isinstance(value, str):
            attr = "CRED_PERSIST_" + value.replace(" ", "_").upper()
            value = globals().get(attr, CRED_PERSIST_ENTERPRISE)
        setattr(keyring, "_persist", value)


class DecodingCredential(dict):
    @property
    def value(self):
        """
        Attempt to decode the credential blob as UTF-16 then UTF-8.
        """

        cred = self["CredentialBlob"]

        # NOTE if we have our metadata, we know how to decode
        if ATTRIBUTE_KEYWORD in self:
            return cred.decode(self[ATTRIBUTE_KEYWORD]["encoding"])

        try:
            return cred.decode("utf-16")
        except UnicodeDecodeError:
            decoded_cred_utf8 = cred.decode("utf-8")
            log.warning(
                "Retrieved an UTF-8 encoded credential not created by keyring."
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
    for details on the implementation, but here"s the gist:

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
        return f"{username}@{service}"

    def _discover_max_password_bytes(self):
        def test_length(length):
            try:
                # NOTE relies on character "a" mapping to a single wchar_t (i.e. 2 bytes)
                try:
                    self._set_password("__probe_target__", "username", "a" * length)
                except Exception as e:
                    if not (isinstance(e, CredError) and e.winerror == 1783):
                        log.exception(f"_set_password raised {e=}")
                    raise
                self._delete_password("__probe_target__")
                return True
            except CredError as e:
                if e.winerror == 1783 and e.funcname == "CredWrite":
                    return False
                else:
                    log.exception("unexpected CredError")
                    return False
            except Exception:
                log.exception("unexpected Exception")

        # first try to confirm observed max bytes of 2560
        if test_length(2560) and not test_length(2561):
            return 2560

        # otherwise, use binary search
        start, end = 1, MAX_PASSWORD_BYTES // 2
        while start <= end:
            mid = (start + end) // 2
            if test_length(mid):
                start = mid + 1
            else:
                end = mid - 1
        return end

    def __init__(self, *arg, **kw):
        super().__init__(*arg, **kw)

        # prevent sharding during self._discover_max_password_bytes
        self._is_init = True
        self._max_password_bytes = self._discover_max_password_bytes()
        self._is_init = False

    def get_password(self, service, username):
        # first attempt to get the password under the service name
        creds = self._get_password(service)
        if not creds or creds["UserName"] != username:
            # It wasn't found so attempt to get it with the compound name
            creds = self._get_password(self._compound_name(username, service))
        if not creds:
            return None
        password = creds.value
        return password

    def _get_password_inner(self, target):
        try:
            res = CredRead(Type=CRED_TYPE_GENERIC, TargetName=target)
        except CredError as e:
            if e.winerror == 1168 and e.funcname == "CredRead":  # not found
                return None
            raise
        return DecodingCredential(res)

    def _get_password(self, target):
        creds = self._get_password_inner(target)
        if creds and ATTRIBUTE_KEYWORD in creds and creds[ATTRIBUTE_KEYWORD]["max_shards"] > 1:
            for i in range(1, creds[ATTRIBUTE_KEYWORD]["max_shards"]):
                shard = self._get_password_inner(TARGET_SHARD.format(target=target, n=i))
                if not shard:
                    log.critical(f"expected shard {i} not found; {creds[ATTRIBUTE_KEYWORD]}")
                    return creds
                else:
                    creds["CredentialBlob"] += shard["CredentialBlob"]
        return creds

    def set_password(self, service, username, password):
        existing_pw = self._get_password(service)
        if existing_pw:
            existing_username = existing_pw["UserName"]
            if existing_username != username:
                # resave the existing password using a compound target
                target = self._compound_name(existing_username, service)
                self._set_password(target, existing_username, existing_pw.value)
        self._set_password(service, username, str(password))

    def _set_password(self, target, username, password):
        pwd_utf8_bytes = password.encode("utf-8")
        pwd_len = len(pwd_utf8_bytes)

        if pwd_len > MAX_PASSWORD_BYTES:
            raise ValueError(MAX_PASSWORD_BYTES, "_set_password: {pwd_len=} exceeds {MAX_PASSWORD_BYTES=}")

        n = MAX_PASSWORD_BYTES if self._is_init else self._max_password_bytes
        max_shards = max((pwd_len + n - 1) // n, 1)

        for i in range(0, max_shards):
            shard = pwd_utf8_bytes[i * n: (i + 1) * n]

            credential = dict(
                Type=CRED_TYPE_GENERIC,
                TargetName=TARGET_SHARD.format(target=target, n=i) if i else target,
                UserName=username,
                CredentialBlob=shard,
                Comment="Stored using python-keyring",
                Persist=self.persist,
                _shard_num=i,
                _max_shards=max_shards
            )
            CredWrite(credential, 0)

    def delete_password(self, service, username):
        compound = self._compound_name(username, service)
        deleted = False
        for target in service, compound:
            existing_pw = self._get_password(target)
            if existing_pw and existing_pw["UserName"] == username:
                deleted = True
                self._delete_password(target)
        if not deleted:
            raise PasswordDeleteError(service)

    def _delete_password_inner(self, target):
        try:
            CredDelete(Type=CRED_TYPE_GENERIC, TargetName=target)
            return True
        except CredError as e:
            if e.winerror == 1168 and e.funcname == "CredDelete":  # not found
                return
            raise

    def _delete_password(self, target):
        deleted = self._delete_password_inner(target)

        if deleted and not self._is_init:
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
        return SimpleCredential(res["UserName"], res.value)
