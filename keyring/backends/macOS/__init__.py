import platform
import os
from os.path import exists

from ...backend import KeyringBackend
from ...errors import PasswordSetError
from ...errors import PasswordDeleteError
from ...errors import KeyringLocked
from ...errors import KeyringError
from ...util import properties

try:
    from . import api
except Exception:
    pass


class Keyring(KeyringBackend):
    """macOS Keychain"""

    # keychain = os.environ.get('KEYCHAIN_PATH')
    # "Path to keychain file, overriding default. function param "

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        Preferred for all macOS environments.
        """
        if platform.system() != 'Darwin':
            raise RuntimeError("macOS required")
        if 'api' not in globals():
            raise RuntimeError("Security API unavailable")
        return 5

    def set_password(self, service, username, password, keychain=""):
        if username is None:
            username = ''

        if keychain != "":
            if not exists(keychain):
                raise KeyringLocked("Can't open specified keychain")
        elif os.environ.get('KEYCHAIN_PATH') != "":
            keychain = os.environ.get('KEYCHAIN_PATH')

        try:
            api.set_generic_password(keychain, service, username, password)
        except api.KeychainDenied as e:
            raise KeyringLocked("Can't store password on keychain: " "{}".format(e))
        except api.Error as e:
            raise PasswordSetError("Can't store password on keychain: " "{}".format(e))

    def get_password(self, service, username, keychain=""):
        if username is None:
            username = ''

        if keychain != "":
            if not exists(keychain):
                raise KeyringLocked("Can't open specified keychain")
        elif os.environ.get('KEYCHAIN_PATH') != "":
            keychain = os.environ.get('KEYCHAIN_PATH')

        try:
            return api.find_generic_password(keychain, service, username)
        except api.NotFound:
            pass
        except api.KeychainDenied as e:
            raise KeyringLocked("Can't get password from keychain: " "{}".format(e))
        except api.Error as e:
            raise KeyringError("Can't get password from keychain: " "{}".format(e))

    def delete_password(self, service, username, keychain=""):
        if username is None:
            username = ''

        if keychain != "":
            if not exists(keychain):
                raise KeyringLocked("Can't open specified keychain")
        elif os.environ.get('KEYCHAIN_PATH') != "":
            keychain = os.environ.get('KEYCHAIN_PATH')

        try:
            return api.delete_generic_password(keychain, service, username)
        except api.Error as e:
            raise PasswordDeleteError(
                "Can't delete password in keychain: " "{}".format(e)
            )
