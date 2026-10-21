from __future__ import annotations

import contextlib
import ctypes
import functools
from ctypes import (
    byref,
    c_bool,
    c_int32,
    c_long,
    c_uint32,
    c_void_p,
)
from ctypes.util import find_library

OS_status = c_int32


class error:
    item_not_found = -25300
    keychain_denied = -128
    sec_auth_failed = -25293
    plist_missing = -67030
    sec_interaction_not_allowed = -25308

kCFStringEncodingUTF8 = 0x08000100

_sec = ctypes.CDLL(find_library('Security'))
_core = ctypes.CDLL(find_library('CoreServices'))
_found = ctypes.CDLL(find_library('Foundation'))

CFDictionaryCreate = _found.CFDictionaryCreate
CFDictionaryCreate.restype = c_void_p
CFDictionaryCreate.argtypes = (
    c_void_p,
    c_void_p,
    c_void_p,
    c_long,
    c_void_p,
    c_void_p,
)

CFStringCreateWithCString = _found.CFStringCreateWithCString
CFStringCreateWithCString.restype = c_void_p
CFStringCreateWithCString.argtypes = [c_void_p, c_void_p, c_uint32]

CFNumberCreate = _found.CFNumberCreate
CFNumberCreate.restype = c_void_p
CFNumberCreate.argtypes = [c_void_p, c_long, ctypes.c_void_p]

SecItemAdd = _sec.SecItemAdd
SecItemAdd.restype = OS_status
SecItemAdd.argtypes = (c_void_p, c_void_p)

SecItemCopyMatching = _sec.SecItemCopyMatching
SecItemCopyMatching.restype = OS_status
SecItemCopyMatching.argtypes = (c_void_p, c_void_p)

SecItemDelete = _sec.SecItemDelete
SecItemDelete.restype = OS_status
SecItemDelete.argtypes = (c_void_p,)

CFDataGetBytePtr = _found.CFDataGetBytePtr
CFDataGetBytePtr.restype = c_void_p
CFDataGetBytePtr.argtypes = (c_void_p,)

CFDataGetLength = _found.CFDataGetLength
CFDataGetLength.restype = c_long
CFDataGetLength.argtypes = (c_void_p,)

CFStringGetLength = _found.CFStringGetLength
CFStringGetLength.restype = c_long
CFStringGetLength.argtypes = (
    c_void_p,
)

CFStringGetMaximumSizeForEncoding = _found.CFStringGetMaximumSizeForEncoding
CFStringGetMaximumSizeForEncoding.restype = c_long
CFStringGetMaximumSizeForEncoding.argtypes = (
    c_long,
    c_uint32
)

CFStringGetCString = _found.CFStringGetCString
CFStringGetCString.restype = c_bool
CFStringGetCString.argtypes = (
    c_void_p,
    c_void_p,
    c_long,
    c_uint32
)

CFDictionaryContainsKey = _found.CFDictionaryContainsKey
CFDictionaryContainsKey.restype = c_bool
CFDictionaryContainsKey.argtypes = (
    c_void_p,
    c_void_p,
)

CFDictionaryGetValue = _found.CFDictionaryGetValue
CFDictionaryGetValue.restype = c_void_p
CFDictionaryGetValue.argtypes = (
    c_void_p,
    c_void_p,
)

CFRelease = _found.CFRelease
CFRelease.restype = None
CFRelease.argtypes = (
    c_void_p,
)

def k_(s):
    return c_void_p.in_dll(_sec, s)


@functools.singledispatch
def create_cf(ob):
    return ob


# explicit bool and int required for Python 3.10 compatibility
@create_cf.register(bool)
@create_cf.register(int)
def _(val: bool | int):
    kCFNumberSInt32Type = 3
    if val.bit_length() > 31:
        raise OverflowError(val)
    return CFNumberCreate(None, kCFNumberSInt32Type, ctypes.byref(c_int32(val)))


@create_cf.register
def _(s: str):
    return CFStringCreateWithCString(None, s.encode('utf8'), kCFStringEncodingUTF8)


def create_query(**kwargs):
    values_cf = []
    try:
        values_cf.extend(create_cf(v) for v in kwargs.values())

        cf_dict = CFDictionaryCreate(
            None,
            (c_void_p * len(kwargs))(*map(k_, kwargs.keys())),
            (c_void_p * len(kwargs))(*values_cf),
            len(kwargs),
            _found.kCFTypeDictionaryKeyCallBacks,
            _found.kCFTypeDictionaryValueCallBacks,
        )

        return cf_dict

    finally:
        # Free memory
        for cf in values_cf:
            # Note: some values here are borrowed CF constants (e.g. kSecClass)
            # We don't own them and releasing them would normally be an over-release.
            # Since they are implemented as immortal CF objects,
            # CFRelease on them is a silent no-op.
            CFRelease(cf)

def cfstr_to_str(data):
    return ctypes.string_at(CFDataGetBytePtr(data), CFDataGetLength(data)).decode(
        'utf-8'
    )

def cfstring_to_str(cf_string):
    str_length = CFStringGetLength(cf_string)
    str_max_size = CFStringGetMaximumSizeForEncoding(str_length, kCFStringEncodingUTF8) + 1
    buffer = ctypes.create_string_buffer(str_max_size)
    if CFStringGetCString(cf_string, buffer, str_max_size, kCFStringEncodingUTF8):
        return ctypes.string_at(buffer).decode('utf-8')
    return None

class Error(Exception):
    @classmethod
    def raise_for_status(cls, status):
        if status == 0:
            return
        if status == error.item_not_found:
            raise NotFound(status, "Item not found")
        if status == error.keychain_denied:
            raise KeychainDenied(status, "Keychain Access Denied")
        if status == error.sec_auth_failed or status == error.plist_missing:
            raise SecAuthFailure(
                status,
                "Security Auth Failure: make sure "
                "executable is signed with codesign util",
            )
        raise cls(status, "Unknown Error")


class NotFound(Error):
    pass


class KeychainDenied(Error):
    pass


class SecAuthFailure(Error):
    pass


def find_generic_password(kc_name, service, username):
    q = None
    data = c_void_p()

    try:
        query = dict(
            kSecClass=k_('kSecClassGenericPassword'),
            kSecMatchLimit=k_('kSecMatchLimitOne'),
            kSecAttrService=service,
            kSecReturnAttributes=True,
            kSecReturnData=True,
        )

        # Use the username in the query, if provided
        if bool(username):
            query = dict(
                query,
                kSecAttrAccount=username,
            )

        q = create_query(**query)

        status = SecItemCopyMatching(q, byref(data))

        Error.raise_for_status(status)

        # Extract username and password from the query
        ret_username = None
        password = None
        if CFDictionaryContainsKey(data, k_('kSecAttrAccount')):
            ret = CFDictionaryGetValue(data, k_('kSecAttrAccount'))
            ret_username = cfstring_to_str(ret)

        if CFDictionaryContainsKey(data, k_('kSecValueData')):
            ret = CFDictionaryGetValue(data, k_('kSecValueData'))
            password = cfstr_to_str(ret)

        return ret_username, password
    finally:
        # Free memory
        if q:
            CFRelease(q)
        if data.value:
            CFRelease(data)


def set_generic_password(name, service, username, password):
    with contextlib.suppress(NotFound):
        delete_generic_password(name, service, username)

    q = None

    try:
        q = create_query(
            kSecClass=k_('kSecClassGenericPassword'),
            kSecAttrService=service,
            kSecAttrAccount=username,
            kSecValueData=password,
        )

        status = SecItemAdd(q, None)
        Error.raise_for_status(status)

    finally:
        # Free memory
        if q:
            CFRelease(q)

def delete_generic_password(name, service, username):
    q = None

    try:
        q = create_query(
            kSecClass=k_('kSecClassGenericPassword'),
            kSecAttrService=service,
            kSecAttrAccount=username,
        )

        status = SecItemDelete(q)
        Error.raise_for_status(status)

    finally:
        # Free memory
        if q:
            CFRelease(q)
