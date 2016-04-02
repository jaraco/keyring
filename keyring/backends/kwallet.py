from __future__ import absolute_import

from ..backend import KeyringBackend
from ..errors import PasswordDeleteError
from ..errors import PasswordSetError
from ..util import properties

try:
    import dbus
except ImportError:
    pass


class DBusKeyring(KeyringBackend):
    """KDE KWallet via D-Bus"""

    folder = 'Python'
    appid = 'Python program'

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        if 'dbus' not in globals():
            raise RuntimeError('python-dbus not installed')
        try:
            bus = dbus.SessionBus()
        except dbus.DBusException as exc:
            raise RuntimeError(exc.get_dbus_message())
        try:
            bus.get_object('org.kde.kwalletd5', '/modules/kwalletd5')
        except dbus.DBusException:
            raise RuntimeError('cannot connect to org.kde.kwalletd5')
        return 4.9

    def __init__(self, *arg, **kw):
        super(DBusKeyring, self).__init__(*arg, **kw)
        self.handle = -1

    def connected(self):
        if self.handle >= 0:
            return True
        bus = dbus.SessionBus()
        wId = 0
        try:
            remote_obj = bus.get_object('org.kde.kwalletd5', '/modules/kwalletd5')
            self.iface = dbus.Interface(remote_obj, 'org.kde.KWallet')
            self.handle = self.iface.open(
                        self.iface.networkWallet(), wId, self.appid)
        except dbus.DBusException:
            self.handle = -1
        if self.handle < 0:
            return False
        if not self.iface.hasFolder(self.handle, self.folder, self.appid):
            self.iface.createFolder(self.handle, self.folder, self.appid)
        return True

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        key = username + '@' + service
        if not self.connected():
            # the user pressed "cancel" when prompted to unlock their keyring.
            return None
        if not self.iface.hasEntry(self.handle, self.folder, key, self.appid):
            return None
        return self.iface.readPassword(
            self.handle, self.folder, key, self.appid)

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        key = username + '@' + service
        if not self.connected():
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordSetError("Cancelled by user")
        self.iface.writePassword(
            self.handle, self.folder, key, password, self.appid)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        key = username + '@' + service
        if not self.connected():
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordDeleteError("Cancelled by user")
        if not self.iface.hasEntry(self.handle, self.folder, key, self.appid):
            raise PasswordDeleteError("Password not found")
        self.iface.removeEntry(self.handle, self.folder, key, self.appid)
