import os

from keyring.backend import KeyringBackend
from keyring.errors import PasswordSetError

class Keyring(KeyringBackend):
    """Gnome Keyring"""

    # Name of the keyring to store the passwords in.
    # Use None for the default keyring.
    KEYRING_NAME = None

    def supported(self):
        try:
            __import__('gnomekeyring')
        except ImportError:
            return -1
        else:
            if ("GNOME_KEYRING_CONTROL" in os.environ and
                "DISPLAY" in os.environ and
                "DBUS_SESSION_BUS_ADDRESS" in os.environ):
                return 1
            else:
                return 0

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        import gnomekeyring

        service = self._safe_string(service)
        username = self._safe_string(username)
        try:
            items = gnomekeyring.find_network_password_sync(username, service)
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
        import gnomekeyring

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
            raise PasswordSetError("cancelled by user")

    def _safe_string(self, source, encoding='utf-8'):
        """Convert unicode to string as gnomekeyring barfs on unicode"""
        if isinstance(source, unicode):
            return source.encode(encoding)
        return str(source)
