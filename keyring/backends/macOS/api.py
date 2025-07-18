from __future__ import annotations

import contextlib
import ctypes
import functools
from ctypes import (
    byref,
    c_int32,
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


_sec = ctypes.CDLL(find_library("Security"))
_core = ctypes.CDLL(find_library("CoreServices"))
_found = ctypes.CDLL(find_library("Foundation"))

CFGetTypeID = _found.CFGetTypeID
CFGetTypeID.restype = c_uint32
CFGetTypeID.argtypes = [c_void_p]

CFArrayGetTypeID = _found.CFArrayGetTypeID
CFArrayGetTypeID.restype = c_uint32

CFAttributedStringGetTypeID = _found.CFAttributedStringGetTypeID
CFAttributedStringGetTypeID.restype = c_uint32

CFCopyTypeIDDescription = _found.CFCopyTypeIDDescription
CFCopyTypeIDDescription.restype = c_void_p
CFCopyTypeIDDescription.argtypes = [c_uint32]

CFArrayGetCount = _found.CFArrayGetCount
CFArrayGetCount.restype = c_int32
CFArrayGetCount.argtypes = [c_void_p]

CFArrayGetValueAtIndex = _found.CFArrayGetValueAtIndex
CFArrayGetValueAtIndex.restype = c_void_p
CFArrayGetValueAtIndex.argtypes = [c_void_p, c_int32]

CFDictionaryGetValue = _found.CFDictionaryGetValue
CFDictionaryGetValue.restype = c_void_p
CFDictionaryGetValue.argtypes = [c_void_p, c_void_p]

CFDictionaryCreate = _found.CFDictionaryCreate
CFDictionaryCreate.restype = c_void_p
CFDictionaryCreate.argtypes = (
    c_void_p,
    c_void_p,
    c_void_p,
    c_int32,
    c_void_p,
    c_void_p,
)

CFStringCreateWithCString = _found.CFStringCreateWithCString
CFStringCreateWithCString.restype = c_void_p
CFStringCreateWithCString.argtypes = [c_void_p, c_void_p, c_uint32]

CFNumberCreate = _found.CFNumberCreate
CFNumberCreate.restype = c_void_p
CFNumberCreate.argtypes = [c_void_p, c_uint32, ctypes.c_void_p]

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
CFDataGetLength.restype = c_int32
CFDataGetLength.argtypes = (c_void_p,)


def k_(s):
    return c_void_p.in_dll(_sec, s)


@functools.singledispatch
def create_cf(ob):
    return ob


# explicit bool and int required for Python 3.10 compatibility
@create_cf.register(bool)
@create_cf.register(int)
def _(val: bool | int):
    if val.bit_length() > 31:
        raise OverflowError(val)
    int32 = 0x9
    return CFNumberCreate(None, int32, ctypes.byref(c_int32(val)))


@create_cf.register
def _(s: str):
    kCFStringEncodingUTF8 = 0x08000100
    return CFStringCreateWithCString(None, s.encode("utf8"), kCFStringEncodingUTF8)


def create_query(**kwargs):
    return CFDictionaryCreate(
        None,
        (c_void_p * len(kwargs))(*map(k_, kwargs.keys())),
        (c_void_p * len(kwargs))(*map(create_cf, kwargs.values())),
        len(kwargs),
        _found.kCFTypeDictionaryKeyCallBacks,
        _found.kCFTypeDictionaryValueCallBacks,
    )


# Convert CFDataRef to Python str
def cfdata_to_str(data):
    b = ctypes.string_at(CFDataGetBytePtr(data), CFDataGetLength(data))
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        # Return hex string if not valid UTF-8
        return b.hex()


# Convert CFStringRef to Python str
def cfstring_to_str(cfstring):
    if not cfstring:
        return None
    # Try fast path
    CFStringGetCStringPtr = _found.CFStringGetCStringPtr
    CFStringGetCStringPtr.restype = ctypes.c_char_p
    CFStringGetCStringPtr.argtypes = [c_void_p, c_uint32]
    kCFStringEncodingUTF8 = 0x08000100
    cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8)
    if cstr:
        return cstr.decode("utf-8")
    # Fallback: use buffer
    CFStringGetCString = _found.CFStringGetCString
    CFStringGetCString.restype = ctypes.c_bool
    CFStringGetCString.argtypes = [c_void_p, ctypes.c_char_p, c_int32, c_uint32]
    buf = ctypes.create_string_buffer(1024)
    if CFStringGetCString(cfstring, buf, 1024, kCFStringEncodingUTF8):
        return buf.value.decode("utf-8")
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


def find_generic_password(kc_name, service, username, not_found_ok=False):
    q = create_query(
        kSecClass=k_("kSecClassGenericPassword"),
        kSecMatchLimit=k_("kSecMatchLimitOne"),
        kSecAttrService=service,
        kSecAttrAccount=username,
        kSecReturnData=True,
    )

    data = c_void_p()
    status = SecItemCopyMatching(q, byref(data))

    if status == error.item_not_found and not_found_ok:
        return

    Error.raise_for_status(status)

    return cfdata_to_str(data)


def set_generic_password(name, service, username, password):
    with contextlib.suppress(NotFound):
        delete_generic_password(name, service, username)

    q = create_query(
        kSecClass=k_("kSecClassGenericPassword"),
        kSecAttrService=service,
        kSecAttrAccount=username,
        kSecValueData=password,
    )

    status = SecItemAdd(q, None)
    Error.raise_for_status(status)


def delete_generic_password(name, service, username):
    q = create_query(
        kSecClass=k_("kSecClassGenericPassword"),
        kSecAttrService=service,
        kSecAttrAccount=username,
    )

    status = SecItemDelete(q)
    Error.raise_for_status(status)


def list_generic_passwords():
    q = create_query(
        kSecClass=k_("kSecClassGenericPassword"),
        kSecMatchLimit=k_("kSecMatchLimitAll"),
        kSecReturnAttributes=True,
    )

    result = ctypes.pointer(c_void_p())
    status = SecItemCopyMatching(q, result)

    if status == error.item_not_found:
        return []

    Error.raise_for_status(status)

    kSecAttrService = k_("kSecAttrService")
    kSecAttrAccount = k_("kSecAttrAccount")

    cf_result = result.contents.value
    if not cf_result:
        return []

    if CFGetTypeID(cf_result) == CFArrayGetTypeID():
        count = CFArrayGetCount(cf_result)
        dicts = [CFArrayGetValueAtIndex(cf_result, i) for i in range(count)]
    else:
        dicts = [cf_result]

    items: list[dict[str, str | None]] = []
    for d in dicts:
        service_cf = CFDictionaryGetValue(d, kSecAttrService)
        account_cf = CFDictionaryGetValue(d, kSecAttrAccount)

        items.append(
            {
                "service": cfstring_to_str(service_cf),
                "account": cfstring_to_str(account_cf),
            }
        )

    return items
