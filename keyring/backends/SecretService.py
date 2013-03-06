import logging

from keyring.backend import KeyringBackend
from keyring.errors import InitError, PasswordDeleteError

log = logging.getLogger(__name__)

class Keyring(KeyringBackend):
    """Secret Service Keyring"""

    def supported(self):
        try:
            import secretstorage
        except ImportError:
            return -1
        from secretstorage.exceptions import SecretServiceNotAvailableException
        try:
            bus = secretstorage.dbus_init()
            secretstorage.Collection(bus)
        except (ImportError, SecretServiceNotAvailableException):
            return -1
        else:
            return 1

    def get_default_collection(self):
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.Collection(bus)
        if collection.is_locked():
            if collection.unlock():
                raise InitError("Failed to unlock the collection!")
        return collection

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        collection = self.get_default_collection()
        items = collection.search_items(
            {"username": username, "service": service})
        for item in items:
            return item.get_secret().decode('utf-8')

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        collection = self.get_default_collection()
        attributes = {
            "application": "python-keyring",
            "service": service,
            "username": username
            }
        label = "%s @ %s" % (username, service)
        collection.create_item(label, attributes, password, replace=True)

    def delete_password(self, service, username):
        """Delete the stored password (only the first one)
        """
        collection = self.get_default_collection()
        attributes = {
            "application": "python-keyring",
            "service": service,
            "username": username
            }
        items = collection.search_items(attributes)
        for item in items:
            return item.delete()
        raise PasswordDeleteError("No such password!")
