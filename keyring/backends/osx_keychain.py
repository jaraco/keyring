#!/usr/bin/python

import sys
if sys.platform != 'darwin':
    raise ImportError('Mac OS X only module')

from ctypes import CDLL, CFUNCTYPE, c_void_p, c_uint32, \
    c_int32, c_char_p, byref, POINTER, memmove, create_string_buffer

# Types

SecKeychainRef     = c_void_p
SecKeychainItemRef = c_void_p
OSStatus           = c_int32

# Constants

errSecSuccess                = 0
errSecUnimplemented          = -4
errSecParam                  = -50
errSecAllocate               = -108

errSecNotAvailable           = -25291
errSecReadOnly               = -25292
errSecAuthFailed             = -25293
errSecNoSuchKeychain         = -25294
errSecInvalidKeychain        = -25295
errSecDuplicateKeychain      = -25296
errSecDuplicateCallback      = -25297
errSecInvalidCallback        = -25298
errSecDuplicateItem          = -25299
errSecItemNotFound           = -25300
errSecBufferTooSmall         = -25301
errSecDataTooLarge           = -25302
errSecNoSuchAttr             = -25303
errSecInvalidItemRef         = -25304
errSecInvalidSearchRef       = -25305
errSecNoSuchClass            = -25306
errSecNoDefaultKeychain      = -25307
errSecInteractionNotAllowed  = -25308
errSecReadOnlyAttr           = -25309
errSecWrongSecVersion        = -25310
errSecKeySizeNotAllowed      = -25311
errSecNoStorageModule        = -25312
errSecNoCertificateModule    = -25313
errSecNoPolicyModule         = -25314
errSecInteractionRequired    = -25315
errSecDataNotAvailable       = -25316
errSecDataNotModifiable      = -25317
errSecCreateChainFailed      = -25318
errSecInvalidPrefsDomain     = -25319

errSecACLNotSimple           = -25240
errSecPolicyNotFound         = -25241
errSecInvalidTrustSetting    = -25242
errSecNoAccessForItem        = -25243
errSecInvalidOwnerEdit       = -25244
errSecTrustNotAvailable      = -25245
errSecUnsupportedFormat      = -25256
errSecUnknownFormat          = -25257
errSecKeyIsSensitive         = -25258
errSecMultiplePrivKeys       = -25259
errSecPassphraseRequired     = -25260
errSecInvalidPasswordRef     = -25261
errSecInvalidTrustSettings   = -25262
errSecNoTrustSettings        = -25263
errSecPkcs12VerifyFailure    = -25264

errSecDecode                 = -26275

# Functions

_dll = CDLL('/System/Library/Frameworks/Security.framework/Versions/A/Security')
_core = CDLL('/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices')

SecKeychainOpen = CFUNCTYPE(OSStatus, c_char_p, POINTER(SecKeychainRef))(('SecKeychainOpen', _dll))
SecKeychainFindGenericPassword = CFUNCTYPE(OSStatus, SecKeychainRef, c_uint32,
                                           c_char_p, c_uint32, c_char_p,
                                           POINTER(c_uint32), POINTER(c_void_p),
                                           POINTER(SecKeychainItemRef))(('SecKeychainFindGenericPassword', _dll))
SecKeychainAddGenericPassword = CFUNCTYPE(OSStatus, SecKeychainRef, c_uint32, c_char_p,
                                          c_uint32, c_char_p, c_uint32,
                                          c_char_p, POINTER(SecKeychainItemRef))(('SecKeychainAddGenericPassword', _dll))
SecKeychainItemModifyAttributesAndData = CFUNCTYPE(OSStatus, SecKeychainItemRef, c_void_p, c_uint32, c_void_p)(('SecKeychainItemModifyAttributesAndData', _dll))
SecKeychainItemFreeContent = CFUNCTYPE(OSStatus, c_void_p, c_void_p)(('SecKeychainItemFreeContent', _dll))

def password_set(realmstring, username, password):
    if username is None:
        username = ''

    keychain = SecKeychainRef()
    if SecKeychainOpen('login.keychain', byref(keychain)):
        raise OSError("Can't access the login keychain")

    try:
        item = SecKeychainItemRef()
        status = SecKeychainFindGenericPassword(keychain, len(realmstring), realmstring, len(username), username, None, None, byref(item))
        if status:
            if status == errSecItemNotFound:
                status = SecKeychainAddGenericPassword(keychain, len(realmstring), realmstring, len(username), username, len(password), password, None)
        else:
            status = SecKeychainItemModifyAttributesAndData(item, None, len(password), password)
            _core.CFRelease(item)

        if status:
            raise OSError("Can't store password in keychain")
    finally:
        _core.CFRelease(keychain)

def password_get(realmstring, username):
    if username is None:
        username = ''

    keychain = SecKeychainRef()
    if SecKeychainOpen('login.keychain', byref(keychain)):
        raise OSError("Can't access the login keychain")

    try:
        length = c_uint32()
        data = c_void_p()
        status = SecKeychainFindGenericPassword(keychain, len(realmstring), realmstring,
                                                len(username), username,
                                                byref(length), byref(data), None)
        if status == 0:
            password = create_string_buffer(length.value)
            memmove(password, data.value, length.value)
            password = password.raw
            SecKeychainItemFreeContent(None, data)
        elif status == errSecItemNotFound:
            password = None
        else:
            raise OSError("Can't fetch password from system")
        return password
    finally:
        _core.CFRelease(keychain)

