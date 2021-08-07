from contextlib import closing
import logging

from ..util import properties
from ..backend import KeyringBackend
from ..credentials import SimpleCredential
from ..errors import (
    PasswordDeleteError,
    ExceptionRaisedContext,
    KeyringLocked,
)

available = False
try:
    import gi
    gi.require_version('Secret', '1')
    from gi.repository import Secret
    available = True
except ImportError:
    pass

log = logging.getLogger(__name__)


class Keyring(KeyringBackend):
    """libsecret Keyring"""

    appid = 'Python keyring library'
    if available:
        schema = Secret.Schema.new(
            "org.freedesktop.Secret.Generic",
            Secret.SchemaFlags.NONE,
            {
                "application": Secret.SchemaAttributeType.STRING,
                "service": Secret.SchemaAttributeType.STRING,
                "username": Secret.SchemaAttributeType.STRING,
            }
        )

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        with ExceptionRaisedContext() as exc:
            Secret.__name__
        if exc:
            raise RuntimeError("libsecret required")
        return 5

    def get_password(self, service, username):
        """Get password of the username for the service"""
        attributes = {
            "application": self.appid,
            "service": service,
            "username": username,
        }
        items = Secret.password_search_sync(self.schema, attributes,
                                            Secret.SearchFlags.UNLOCK, None)
        for item in items:
            return item.retrieve_secret_sync().get_text()

    def set_password(self, service, username, password):
        """Set password for the username of the service"""
        collection = Secret.COLLECTION_DEFAULT
        attributes = {
            "application": self.appid,
            "service": service,
            "username": username,
        }
        label = "Password for '{}' on '{}'".format(username, service)
        Secret.password_store_sync(self.schema, attributes, collection,
                                   label, password, None)

    def delete_password(self, service, username):
        """Delete the stored password (only the first one)"""
        attributes = {
            "application": self.appid,
            "service": service,
            "username": username,
        }
        items = Secret.password_search_sync(self.schema, attributes,
                                            Secret.SearchFlags.UNLOCK, None)
        for item in items:
            removed = Secret.password_clear_sync(self.schema,
                                                 item.get_attributes(), None)
            return removed
        raise PasswordDeleteError("No such password!")

    def get_credential(self, service, username):
        """Get the first username and password for a service.
        Return a Credential instance

        The username can be omitted, but if there is one, it will use get_password
        and return a SimpleCredential containing  the username and password
        Otherwise, it will return the first username and password combo that it finds.
        """
        query = {"service": service}
        if username:
            query["username"] = username
        items = Secret.password_search_sync(self.schema, query,
                                            Secret.SearchFlags.UNLOCK, None)
        for item in items:
            username = item.get_attributes().get("username")
            return SimpleCredential(username, item.retrieve_secret_sync().get_text())
