import contextlib
import ctypes
from ctypes import c_void_p, c_uint16, c_uint32, c_int32, c_char_p, POINTER

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


SecKeychainCopyDefault = _sec.SecKeychainCopyDefault
SecKeychainCopyDefault.argtypes = POINTER(sec_keychain_ref),
SecKeychainCopyDefault.restype = OS_status


@contextlib.contextmanager
def open(name):
    ref = sec_keychain_ref()
    if name is None:
        res = SecKeychainCopyDefault(ref)
        msg = "Unable to open default keychain"
    else:
        res = SecKeychainOpen(name.encode('utf-8'), ref)
        msg = "Unable to open keychain {name}".format(**locals())
    if res:
        raise OSError(msg)
    try:
        yield ref
    finally:
        _core.CFRelease(ref)

SecKeychainFindGenericPassword = _sec.SecKeychainFindGenericPassword
SecKeychainFindGenericPassword.argtypes = (
    sec_keychain_ref,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    POINTER(c_uint32),  # passwordLength
    POINTER(c_void_p),  # passwordData
    POINTER(sec_keychain_item_ref),  # itemRef
)
SecKeychainFindGenericPassword.restype = OS_status

SecKeychainFindInternetPassword = _sec.SecKeychainFindInternetPassword
SecKeychainFindInternetPassword.argtypes = (
    sec_keychain_ref, # keychainOrArray
    c_uint32,  # serverNameLength
    c_char_p,  # serverName
    c_uint32,  # securityDomainLength
    c_char_p,  # securityDomain
    c_uint32,  # accountNameLength
    c_char_p,  # accountName
    c_uint32,  # pathLength
    c_char_p,  # path
    c_uint16,  # port
    c_void_p,  # SecProtocolType protocol,
    c_void_p,  # SecAuthenticationType authenticationType,
    POINTER(c_uint32),  # passwordLength
    POINTER(c_void_p),  # passwordData
    POINTER(sec_keychain_item_ref),  # itemRef
)
SecKeychainFindInternetPassword.restype = OS_status

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
