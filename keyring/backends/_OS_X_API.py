import contextlib
import ctypes
from ctypes import (
    c_void_p, c_uint32,
    c_int32, c_char_p, POINTER,
)

sec_keychain_ref = sec_keychain_item_ref = c_void_p
OS_status = c_int32

class error:
    item_not_found = -25300

fw = '/System/Library/Frameworks/{name}.framework/Versions/A/{name}'.format
_sec = ctypes.CDLL(fw(name='Security'))
_core = ctypes.CDLL(fw(name='CoreServices'))


SecKeychainOpen = _sec.SecKeychainOpen
SecKeychainOpen.argtypes = (
    c_char_p,
    POINTER(sec_keychain_ref),
)
SecKeychainOpen.restype = OS_status

@contextlib.contextmanager
def open(name):
    ref = sec_keychain_ref()
    res = SecKeychainOpen(name.encode('utf-8'), ref)
    if res:
        raise OSError("Unable to open keychain {name}".format(**locals()))
    try:
        yield res
    finally:
        _core.CFRelease(ref)

SecKeychainFindGenericPassword = _sec.SecKeychainFindGenericPassword
SecKeychainFindGenericPassword.argtypes = (
    sec_keychain_ref,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    POINTER(c_uint32),
    POINTER(c_void_p),
    POINTER(sec_keychain_item_ref),
)
SecKeychainFindGenericPassword.restype = OS_status

SecKeychainAddGenericPassword = _sec.SecKeychainAddGenericPassword
SecKeychainAddGenericPassword.argtypes = (
    sec_keychain_ref,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    POINTER(sec_keychain_item_ref),
)
SecKeychainAddGenericPassword.restype = OS_status

SecKeychainItemModifyAttributesAndData = _sec.SecKeychainItemModifyAttributesAndData
SecKeychainItemModifyAttributesAndData.argtypes = (
    sec_keychain_item_ref, c_void_p, c_uint32, c_void_p,
)
SecKeychainItemModifyAttributesAndData.restype = OS_status

SecKeychainItemFreeContent = _sec.SecKeychainItemFreeContent
SecKeychainItemFreeContent.argtypes = (
    c_void_p, c_void_p,
)
SecKeychainItemFreeContent.restype = OS_status

SecKeychainItemDelete = _sec.SecKeychainItemDelete
SecKeychainItemDelete.argtypes = sec_keychain_item_ref,
SecKeychainItemDelete.restype = OS_status
