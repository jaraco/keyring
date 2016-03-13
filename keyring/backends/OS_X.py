import platform
import re
import ctypes

from ..backend import KeyringBackend
from ..errors import PasswordSetError
from ..errors import PasswordDeleteError
from ..util import properties
from ..py27compat import unicode_str

try:
    from . import _OS_X_API as api
except Exception:
    pass


class SecurityCommand(unicode_str):
    """
    A string suitable for passing as the 'command' parameter to the
    OS X 'security' command.
    """
    def __new__(cls, cmd, store='generic'):
        cmd = '%(cmd)s-%(store)s-password' % vars()
        return super(SecurityCommand, cls).__new__(cls, cmd)


class Keyring(KeyringBackend):
    """Mac OS X Keychain"""

    # regex for extracting password from security call
    password_regex = re.compile("""password:\s*(?:0x(?P<hex>[0-9A-F]+)\s*)?"""
                                """(?:"(?P<pw>.*)")?""")
    store = 'generic'

    keychain = None
    "Pathname to keychain filename, overriding default keychain."

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        Preferred for all OS X environments.
        """
        if platform.system() != 'Darwin':
            raise RuntimeError("OS X required")
        return 5

    def set_password(self, service, username, password):
        if username is None:
            username = ''

        username = username.encode('utf-8')
        service = service.encode('utf-8')
        password = password.encode('utf-8')
        with api.open('login.keychain') as keychain:
            item = api.sec_keychain_item_ref()
            status = api.SecKeychainFindGenericPassword(
                keychain,
                len(service), service,
                len(username), username, None,
                None, item)
            if status:
                if status == api.error.item_not_found:
                    status = api.SecKeychainAddGenericPassword(
                        keychain,
                        len(service), service,
                        len(username), username,
                        len(password), password, None)
            else:
                status = api.SecKeychainItemModifyAttributesAndData(
                    item, None, len(password), password)
                api._core.CFRelease(item)

            if status:
                raise PasswordSetError("Can't store password in keychain")

    def get_password(self, service, username):
        if username is None:
            username = ''

        username = username.encode('utf-8')
        service = service.encode('utf-8')
        with api.open('login.keychain') as keychain:
            length = api.c_uint32()
            data = api.c_void_p()
            status = api.SecKeychainFindGenericPassword(
                keychain,
                len(service),
                service,
                len(username),
                username,
                length,
                data,
                None,
            )
            if status == 0:
                password = ctypes.create_string_buffer(length.value)
                ctypes.memmove(password, data.value, length.value)
                password = password.raw.decode('utf-8')
                api.SecKeychainItemFreeContent(None, data)
            elif status == api.error.item_not_found:
                password = None
            else:
                raise OSError("Can't fetch password from system")
            return password

    def delete_password(self, service, username):
        if username is None:
            username = ''

        username = username.encode('utf-8')
        service = service.encode('utf-8')
        with api.open('login.keychain') as keychain:
            length = api.c_uint32()
            data = api.c_void_p()
            item = api.sec_keychain_item_ref()
            status = api.SecKeychainFindGenericPassword(
                keychain,
                len(service),
                service,
                len(username),
                username,
                length,
                data,
                item,
            )
            if status != 0:
                raise PasswordDeleteError("Can't delete password in keychain")

            api.SecKeychainItemDelete(item)
            api._core.CFRelease(item)
