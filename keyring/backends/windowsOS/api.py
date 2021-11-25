import json
from weakref import WeakKeyDictionary

import cffi

ATTRIBUTE_KEYWORD = 'keyring_metadata'

ffi = cffi.FFI()

ffi.set_unicode(True)

advapi32 = ffi.dlopen('advapi32.dll')

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
    'Type', 'TargetName', 'Persist',
    'UserName', 'Comment', 'CredentialBlob'))


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


def _raise_error(function_name=''):
    code, message = ffi.getwinerror()
    raise CredError(code, function_name, message)


def PCREDENTIAL_ATTRIBUTE(value=None):
    return ffi.new('PCREDENTIAL_ATTRIBUTE', ffi.NULL if value is None else value)


def PPCREDENTIAL_ATTRIBUTE(value=None):
    return ffi.new('PCREDENTIAL_ATTRIBUTE*', ffi.NULL if value is None else value)


def PCREDENTIAL(value=None):
    return ffi.new('PCREDENTIAL', ffi.NULL if value is None else value)


def PPCREDENTIAL(value=None):
    return ffi.new('PCREDENTIAL*', ffi.NULL if value is None else value)


_keep_alive = WeakKeyDictionary()


def credential_from_dict(credential, flag=0):
    if flag != 0:
        raise ValueError('flag != 0 not yet supported')

    # region Attributes
    c_attrs = ffi.new('PCREDENTIAL_ATTRIBUTE')[0]
    # values to ref and make sure that they will not go away
    values = []

    value = ffi.new('wchar_t[]', ATTRIBUTE_KEYWORD)
    values.append(value)
    c_attrs.Keyword = ffi.cast('LPTSTR', value)

    c_attrs.Flags = 0

    metadata = json.dumps(
        dict(
            max_shards=credential['_max_shards'],
            shard_num=credential['_shard_num'],
            encoding=credential['encoding']
        )
    )
    metadata_bytes = metadata.encode('utf-8')
    value = ffi.new('BYTE[]', metadata_bytes)
    values.append(value)
    # new adds a NULL at the end that we do not want.
    c_attrs.ValueSize = ffi.sizeof(value) - ffi.sizeof('char')
    c_attrs.Value = ffi.cast('LPBYTE', value)

    # keep values alive until c_attrs goes away.
    _keep_alive[c_attrs] = tuple(values)
    # endregion

    c_creds = ffi.new('PCREDENTIAL')[0]
    # values to ref and make sure that they will not go away
    values = []
    for key in SUPPORTED_CREDKEYS:
        if key in credential:
            if key == 'CredentialBlob':
                blob = credential['CredentialBlob']
                blob_data = ffi.new('BYTE[]', blob)
                values.append(blob_data)
                # new adds a NULL at the end that we do not want.
                c_creds.CredentialBlobSize = ffi.sizeof(blob_data) - ffi.sizeof('char')
                c_creds.CredentialBlob = ffi.cast('LPBYTE', blob_data)
            elif key in ('Type', 'Persist'):
                setattr(c_creds, key, credential[key])
            else:
                blob = credential[key]
                value = ffi.new('wchar_t[]', blob)
                values.append(value)
                setattr(c_creds, key, ffi.cast('LPTSTR', value))

    c_creds.AttributeCount = 1
    c_creds.Attributes = PCREDENTIAL_ATTRIBUTE(c_attrs)
    values.append(c_attrs)

    # keep values alive until c_creds goes away.
    _keep_alive[c_creds] = tuple(values)
    return c_creds


def credential_to_dict(pc_creds):
    credentials = {}
    for key in SUPPORTED_CREDKEYS:
        if key == 'CredentialBlob':
            data = ffi.buffer(pc_creds.CredentialBlob, pc_creds.CredentialBlobSize)[:]  # [:] causes copy
        elif key in ('Type', 'Persist'):
            data = int(getattr(pc_creds, key))
        else:
            string_pointer = getattr(pc_creds, key)
            if string_pointer == ffi.NULL:
                data = ''
            else:
                data = ffi.string(string_pointer)
        credentials[key] = data

    if hasattr(pc_creds, 'AttributeCount') and hasattr(pc_creds, 'Attributes'):
        credentials['AttributeCount'] = int(pc_creds.AttributeCount)
        if pc_creds.AttributeCount == 1 and ffi.string(pc_creds.Attributes.Keyword) == ATTRIBUTE_KEYWORD:
            metadata_bytes = ffi.buffer(pc_creds.Attributes.Value, pc_creds.Attributes.ValueSize)[:]
            metadata_string = metadata_bytes.decode('utf-8')
            credentials[ATTRIBUTE_KEYWORD] = json.loads(metadata_string)

    return credentials


def CredWrite(Credential, Flags=CRED_PRESERVE_CREDENTIAL_BLOB):
    c_creds = credential_from_dict(Credential, Flags)
    c_pcreds = PCREDENTIAL(c_creds)
    if advapi32.CredWriteW(c_pcreds, Flags) == 0:
        _raise_error('CredWrite')


def CredRead(TargetName, Type, Flags=0):
    flag = 0
    ppcreds = PPCREDENTIAL()
    if advapi32.CredReadW(TargetName, Type, flag, ppcreds) == 0:
        _raise_error('CredRead')
    pcreds = ppcreds[0]

    try:
        res = credential_to_dict(pcreds[0])
    finally:
        advapi32.CredFree(pcreds)

    return res


def CredDelete(TargetName, Type, Flags=0):
    if advapi32.CredDeleteW(TargetName, Type, Flags) == 0:
        _raise_error('CredDelete')
