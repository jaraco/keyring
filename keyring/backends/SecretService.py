from keyring.backend import KeyringBackend

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

    def _str_to_dbus_str(self, s, strict=False):
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
            logger.exception("Failed to convert '%s' to unicode" % s)
            if strict:
                raise
            else:
                return unicode(s, errors='replace')

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        import dbus
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        bus = dbus.SessionBus()
        service_obj = bus.get_object('org.freedesktop.secrets',
            '/org/freedesktop/secrets')
        service_iface = dbus.Interface(service_obj,
            'org.freedesktop.Secret.Service')
        unlocked, locked = service_iface.SearchItems(
            {"username": username, "service": service})
        _, session = service_iface.OpenSession("plain", "")
        no_longer_locked, prompt = service_iface.Unlock(locked)
        assert prompt == "/"
        secrets = service_iface.GetSecrets(unlocked + locked, session,
            byte_arrays=True)
        for item_path, secret in secrets.iteritems():
            return unicode(secret[2])
        return None

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        import dbus
        service = self._str_to_dbus_str(service)
        username = self._str_to_dbus_str(username)
        password = self._str_to_dbus_str(password)
        bus = dbus.SessionBus()
        service_obj = bus.get_object('org.freedesktop.secrets',
            '/org/freedesktop/secrets')
        service_iface = dbus.Interface(service_obj,
            'org.freedesktop.Secret.Service')
        collection_obj = bus.get_object(
            'org.freedesktop.secrets',
            '/org/freedesktop/secrets/aliases/default')
        collection = dbus.Interface(collection_obj,
            'org.freedesktop.Secret.Collection')
        attributes = {
            "service": service,
            "username": username
            }
        _, session = service_iface.OpenSession("plain", "")

        secret = dbus.Struct(
            (session, "", dbus.ByteArray(password), "application/octet-stream"))
        properties = {
            "org.freedesktop.Secret.Item.Label": "%s @ %s" % (
                username, service),
            "org.freedesktop.Secret.Item.Attributes": attributes}
        (item, prompt) = collection.CreateItem(properties, secret,
            True)
        assert prompt == "/"

    def delete_password(self, service, username):
        raise NotImplementedError()
