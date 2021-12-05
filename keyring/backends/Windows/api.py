from ctypes import (
    POINTER,
    Structure,
    WinError,
    byref,
    c_char_p,
    c_uint32,
    c_wchar_p,
    cast,
    pointer,
    string_at,
    windll,
)
from ctypes.wintypes import BOOL, DWORD, LPBYTE, LPVOID

ATTRIBUTE_KEYWORD = 'python-keyring:authstate'


# region ctypes wrapper structures


class FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime', c_uint32),
        ('dwHighDateTime', c_uint32),
    ]

    def asdict(self):
        return {field: getattr(self, field) for field, _ in self._fields_}


class CREDENTIAL_ATTRIBUTEW(Structure):
    _fields_ = [
        ('Keyword', c_wchar_p),
        ('Flags', DWORD),
        ('ValueSize', DWORD),
        ('Value', LPBYTE),
    ]

    def asdict(self):
        result = {}

        for field, _ in self._fields_:
            value = getattr(self, field)

            if field != 'Value':
                result[field] = value
            else:
                result[field] = string_at(value, getattr(self, 'ValueSize'))

        return result


class CREDENTIALW(Structure):
    _fields_ = [
        ('Flags', DWORD),
        ('Type', DWORD),
        ('TargetName', c_wchar_p),
        ('Comment', c_wchar_p),
        ('LastWritten', FILETIME),
        ('CredentialBlobSize', DWORD),
        ('CredentialBlob', LPBYTE),
        ('Persist', DWORD),
        ('AttributeCount', DWORD),
        ('Attributes', POINTER(CREDENTIAL_ATTRIBUTEW)),
        ('TargetAlias', c_wchar_p),
        ('UserName', c_wchar_p),
    ]

    def asdict(self):
        result = {}

        for field, _ in self._fields_:
            value = getattr(self, field)

            if field == 'LastWritten':
                result[field] = value.asdict()
            elif field == 'Attributes':
                attr_dict = {}
                for i in range(result['AttributeCount']):
                    if value[i]:  # NULL pointer is treated as False by ctypes
                        attr = value[i].asdict()
                        attr_dict[attr['Keyword']] = attr
                result[field] = attr_dict
            elif field == 'CredentialBlob':
                blob = string_at(value, getattr(self, 'CredentialBlobSize'))
                result[field] = blob
            else:
                result[field] = value

        return result


# endregion


# region Win32 API declarations


def errcheck(result, func, args):
    if not result:
        raise WinError()


_CredReadW = windll.advapi32.CredReadW
_CredReadW.argtypes = [c_wchar_p, DWORD, DWORD, POINTER(POINTER(CREDENTIALW))]
_CredReadW.restype = BOOL
_CredReadW.errcheck = errcheck  # type: ignore

_CredWriteW = windll.advapi32.CredWriteW
_CredWriteW.argtypes = [POINTER(CREDENTIALW), DWORD]
_CredWriteW.restype = BOOL
_CredWriteW.errcheck = errcheck  # type: ignore

_CredDeleteW = windll.advapi32.CredDeleteW
_CredDeleteW.argtypes = [c_wchar_p, DWORD, DWORD]
_CredDeleteW.restype = BOOL
_CredDeleteW.errcheck = errcheck  # type: ignore

_CredEnumerateW = windll.advapi32.CredEnumerateW
_CredEnumerateW.argtypes = [
    c_wchar_p,
    DWORD,
    POINTER(DWORD),
    POINTER(POINTER(POINTER(CREDENTIALW))),
]
_CredEnumerateW.restype = BOOL
_CredEnumerateW.errcheck = errcheck  # type: ignore

_CredFree = windll.advapi32.CredFree
_CredFree.argtypes = [LPVOID]
_CredFree.restype = None

CRED_TYPE_GENERIC = 1
CRED_PERSIST_SESSION = 1
CRED_PERSIST_LOCAL_MACHINE = 2
CRED_PERSIST_ENTERPRISE = 3
CRED_ENUMERATE_ALL_CREDENTIALS = 1
CRED_MAX_VALUE_SIZE = 256
CRED_MAX_ATTRIBUTES = 64
MAX_PASSWORD_BYTES = CRED_MAX_VALUE_SIZE * CRED_MAX_ATTRIBUTES


# endregion

# region API


def CredRead(Type, TargetName):
    pcred = pointer(CREDENTIALW())
    _CredReadW(TargetName, Type, 0, byref(pcred))
    credential = pcred.contents.asdict()
    _CredFree(pcred)
    return credential


def CredReadFromAttributes(Type, TargetName, Credential=None, encoding='utf-8'):
    if Credential is None:
        Credential = CredRead(Type, TargetName)

    num_attrs = Credential['AttributeCount']
    if num_attrs > 0:
        attrs = Credential['Attributes']
        accum = b''
        for i, (key, attr) in enumerate(attrs.items()):
            expected_key = '{}:{}'.format(ATTRIBUTE_KEYWORD, str(i))
            if key == expected_key:
                accum += string_at(attr['Value'], attr['ValueSize'])
            else:
                break

        Credential['CredentialBlob'] = accum.decode(encoding)
        Credential['CredentialBlobSize'] = len(Credential['CredentialBlob'])

    return Credential


def _create_attribute(keyword, value):
    return CREDENTIAL_ATTRIBUTEW(
        Keyword=keyword,
        Flags=0,
        ValueSize=len(value),
        Value=cast(c_char_p(value), LPBYTE),
    )


def _password_to_attributes(cred_args, encoding):
    password = cred_args['CredentialBlob']
    pwd_len = len(password)
    encoded_password = password.encode(encoding)
    cred_args['CredentialBlob'] = None
    cred_args['CredentialBlobSize'] = 0

    n = CRED_MAX_VALUE_SIZE
    max_shards = max((pwd_len + n - 1) // n, 1)

    if max_shards > CRED_MAX_ATTRIBUTES:
        raise ValueError(
            MAX_PASSWORD_BYTES,
            'password length {} is greater than max allowed ({})'.format(
                pwd_len, MAX_PASSWORD_BYTES
            ),
        )

    cred_attrs = (CREDENTIAL_ATTRIBUTEW * max_shards)()

    for i in range(0, max_shards):
        keyword = '{}:{}'.format(ATTRIBUTE_KEYWORD, str(i))
        shard = encoded_password[i * n : (i + 1) * n]
        cred_attrs[i] = _create_attribute(keyword, shard)

    cred_args['AttributeCount'] = max_shards
    cred_args['Attributes'] = cred_attrs


# NOTE utf-16-le encodes without BOM, as does pywin32 and pywin32-ctypes
def CredWrite(credential, Flags, encoding='utf-16-le'):
    cred_args = {}
    cred_args.update(credential)

    cred_args['Flags'] = Flags

    if 'TargetAlias' not in cred_args:
        cred_args['TargetAlias'] = None

    if 'AttributeCount' not in cred_args:
        cred_args['AttributeCount'] = 0
    if 'Attributes' not in cred_args:
        cred_args['Attributes'] = None

    password = cred_args['CredentialBlob']
    encoded_password = password.encode(encoding)
    cred_args['CredentialBlob'] = cast(encoded_password, LPBYTE)
    cred_args['CredentialBlobSize'] = len(encoded_password)

    cred = CREDENTIALW(**cred_args)
    _CredWriteW(byref(cred), Flags)


def CredWriteToAttributes(credential, Flags, encoding='utf-8'):
    cred_args = {}
    cred_args.update(credential)

    cred_args['Flags'] = Flags

    if 'TargetAlias' not in cred_args:
        cred_args['TargetAlias'] = None

    # Sets CredentialBlob, CredentialBlobSize, AttributeCount, Attributes
    _password_to_attributes(cred_args, encoding)

    cred = CREDENTIALW(**cred_args)
    _CredWriteW(byref(cred), Flags)


def CredDelete(Type, TargetName):
    _CredDeleteW(TargetName, Type, 0)


def CredEnumerate(Filter=None, Flags=CRED_ENUMERATE_ALL_CREDENTIALS):
    pcount = pointer(DWORD())
    ppcred = POINTER(POINTER(CREDENTIALW))()

    _CredEnumerateW(Filter, Flags, pcount, byref(ppcred))

    entries = []
    for i in range(pcount.contents.value):
        entries.append(ppcred[i].contents.asdict())

    return entries


# endregion
