import os

try:
    import gnomekeyring
except ImportError:
    pass

from keyring.backend import KeyringBackend
from keyring.errors import PasswordSetError, PasswordDeleteError
from keyring.util import properties

class Keyring(KeyringBackend):
    """Gnome Keyring"""

    # Name of the keyring to store the passwords in.
    # Use None for the default keyring.
    KEYRING_NAME = None

    requisite_vars = [
        'GNOME_KEYRING_CONTROL',
        'DISPLAY',
        'DBUS_SESSION_BUS_ADDRESS',
    ]

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        if 'gnomekeyring' not in globals():
            raise RuntimeError("gnomekeyring module required")
        return int(cls.has_requisite_vars())

    @classmethod
    def has_requisite_vars(cls):
        """
        Return True if the requisite environment vars are present in the
        environment.
        """
        return set(cls.requisite_vars).issubset(os.environ)

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        service = self._safe_string(service)
        username = self._safe_string(username)
        try:
            items = gnomekeyring.find_network_password_sync(username, service)
        except gnomekeyring.IOError:
            return None
        except gnomekeyring.NoMatchError:
            return None
        except gnomekeyring.CancelledError:
            # The user pressed "Cancel" when prompted to unlock their keyring.
            return None

        assert len(items) == 1, 'no more than one entry should ever match'
        return items[0]['password']

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        service = self._safe_string(service)
        username = self._safe_string(username)
        password = self._safe_string(password)
        try:
            gnomekeyring.item_create_sync(
                self.KEYRING_NAME, gnomekeyring.ITEM_NETWORK_PASSWORD,
                "Password for '%s' on '%s'" % (username, service),
                {'user': username, 'domain': service},
                password, True)
        except gnomekeyring.CancelledError:
            # The user pressed "Cancel" when prompted to unlock their keyring.
            raise PasswordSetError("Cancelled by user")

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        try:
            items = gnomekeyring.find_network_password_sync(username, service)
            for current in items:
                gnomekeyring.item_delete_sync(current['keyring'],
                                              current['item_id'])
        except gnomekeyring.NoMatchError:
            raise PasswordDeleteError("Password not found")
        except gnomekeyring.CancelledError:
            raise PasswordDeleteError("Cancelled by user")

    def _safe_string(self, source, encoding='utf-8'):
        """Convert unicode to string as gnomekeyring barfs on unicode"""
        if isinstance(source, unicode):
            return source.encode(encoding)
        return str(source)
