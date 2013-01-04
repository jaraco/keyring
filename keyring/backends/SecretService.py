import logging

from keyring.backend import KeyringBackend

log = logging.getLogger(__name__)

class Keyring(KeyringBackend):
    """Secret Service Keyring"""

    def supported(self):
        try:
            import dbus
        except ImportError:
            return -1
        try:
            bus = dbus.SessionBus()
            bus.get_object('org.freedesktop.secrets',
                '/org/freedesktop/secrets')
        except dbus.exceptions.DBusException:
            return -1
        else:
            return 1

    @staticmethod
    def _str_to_dbus_str(s, strict=False):
        """Given a string, do our best to turn it into a unicode compatible
        object.
        """
        if issubclass(s.__class__, unicode):
            # It's already unicode, no problem.
            return s

        # It's not unicode.  Convert it to a unicode string.
        try:
            return unicode(s)
        except UnicodeEncodeError:
            log.exception("Failed to convert '%s' to unicode" % s)
            if strict:
                raise
            else:
                return unicode(s, errors='replace')

    @property
    def secret_service(self):
        import dbus
        bus = dbus.SessionBus()
        service_obj = bus.get_object('org.freedesktop.secrets',
            '/org/freedesktop/secrets')
        return dbus.Interface(service_obj, 'org.freedesktop.Secret.Service')

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        secret_service = self.secret_service
        unlocked, locked = secret_service.SearchItems(
            {"username": username, "service": service})
        _, session = secret_service.OpenSession("plain", "")
        no_longer_locked, prompt = secret_service.Unlock(locked)
        self._check_prompt(prompt)
        secrets = secret_service.GetSecrets(unlocked + locked, session,
            byte_arrays=True)
        for item_path, secret in secrets.iteritems():
            return unicode(secret[2])

    def _check_prompt(self, prompt):
        """
        Ensure we support the supplied prompt value.

        from http://standards.freedesktop.org/secret-service/re01.html:
        Prompt is a prompt object which can be used to unlock the remaining
        objects, or the special value '/' when no prompt is necessary.
        """
        if not prompt == '/':
            raise ValueError("Keyring does not support prompts")

    @property
    def collection(self):
        import dbus
        bus = dbus.SessionBus()
        collection_obj = bus.get_object(
            'org.freedesktop.secrets',
            '/org/freedesktop/secrets/aliases/default')
        return dbus.Interface(collection_obj,
            'org.freedesktop.Secret.Collection')

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        import dbus
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        password = self._str_to_dbus_str(password)
        attributes = {
            "service": service,
            "username": username
            }
        _, session = self.secret_service.OpenSession("plain", "")

        secret = dbus.Struct(
            (session, "", dbus.ByteArray(password), "application/octet-stream"))
        properties = {
            "org.freedesktop.Secret.Item.Label": "%s @ %s" % (
                username, service),
            "org.freedesktop.Secret.Item.Attributes": attributes}
        item, prompt = self.collection.CreateItem(properties, secret, True)
        self._check_prompt(prompt)

    def delete_password(self, service, username):
        raise NotImplementedError()
