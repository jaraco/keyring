import logging
from contextlib import contextmanager

from ..util import properties
from ..backend import KeyringBackend
from ..errors import (InitError, PasswordDeleteError,
                      ExceptionRaisedContext, KeyringLocked)

try:
    import secretstorage
    import secretstorage.exceptions as exceptions
except ImportError:
    pass
except AttributeError:
    # See https://github.com/jaraco/keyring/issues/296
    pass

log = logging.getLogger(__name__)


class Keyring(KeyringBackend):
    """Secret Service Keyring"""
    appid = 'Python keyring library'

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        with ExceptionRaisedContext() as exc:
            secretstorage.__name__
        if exc:
            raise RuntimeError("SecretStorage required")
        if not hasattr(secretstorage, 'get_default_collection'):
            raise RuntimeError("SecretStorage 1.0 or newer required")
        try:
            bus = secretstorage.dbus_init()
            list(secretstorage.get_all_collections(bus))
            bus.sock.close()
        except exceptions.SecretStorageException as e:
            raise RuntimeError(
                "Unable to initialize SecretService: %s" % e)
        return 5

    @contextmanager
    def get_preferred_collection(self):
        """If self.preferred_collection contains a D-Bus path,
        the collection at that address is returned. Otherwise,
        the default collection is returned.
        """
        bus = secretstorage.dbus_init()
        try:
            if hasattr(self, 'preferred_collection'):
                collection = secretstorage.Collection(
                    bus, self.preferred_collection)
            else:
                collection = secretstorage.get_default_collection(bus)
        except exceptions.SecretStorageException as e:
            raise InitError("Failed to create the collection: %s." % e)
        if collection.is_locked():
            collection.unlock()
            if collection.is_locked():  # User dismissed the prompt
                raise KeyringLocked("Failed to unlock the collection!")
        try:
            yield collection
        finally:
            collection.connection.sock.close()

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        with self.get_preferred_collection() as collection:
            items = collection.search_items(
                {"username": username, "service": service})
            for item in items:
                if hasattr(item, 'unlock'):
                    item.unlock()
                if item.is_locked():  # User dismissed the prompt
                    raise KeyringLocked('Failed to unlock the item!')
                return item.get_secret().decode('utf-8')

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        with self.get_preferred_collection() as collection:
            attributes = {
                "application": self.appid,
                "service": service,
                "username": username
            }
            label = "Password for '%s' on '%s'" % (username, service)
            collection.create_item(label, attributes, password, replace=True)

    def delete_password(self, service, username):
        """Delete the stored password (only the first one)
        """
        with self.get_preferred_collection() as collection:
            items = collection.search_items(
                {"username": username, "service": service})
            for item in items:
                return item.delete()
            raise PasswordDeleteError("No such password!")
