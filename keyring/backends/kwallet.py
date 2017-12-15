from __future__ import absolute_import

import sys
import os

from ..backend import KeyringBackend
from ..errors import PasswordDeleteError
from ..errors import PasswordSetError
from ..util import properties

try:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
except ImportError:
    pass
except AttributeError:
    # See https://github.com/jaraco/keyring/issues/296
    pass


class DBusKeyring(KeyringBackend):
    """
    KDE KWallet 5 via D-Bus
    """

    appid = os.path.basename(sys.argv[0]) or 'Python keyring library'
    wallet = None
    bus_name = 'org.kde.kwalletd5'
    object_path = '/modules/kwalletd5'

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        if 'dbus' not in globals():
            raise RuntimeError('python-dbus not installed')
        try:
            bus = dbus.SessionBus(mainloop=DBusGMainLoop())
        except dbus.DBusException as exc:
            raise RuntimeError(exc.get_dbus_message())
        try:
            bus.get_object(cls.bus_name, cls.object_path)
        except dbus.DBusException:
            tmpl = 'cannot connect to {bus_name}'
            msg = tmpl.format(bus_name=cls.bus_name)
            raise RuntimeError(msg)
        return 4.9

    def __init__(self, *arg, **kw):
        super(DBusKeyring, self).__init__(*arg, **kw)
        self.handle = -1

    def _migrate(self, service):
        old_folder = 'Python'
        entry_list = []
        if self.iface.hasFolder(self.handle, old_folder, self.appid):
            entry_list = self.iface.readPasswordList(
                self.handle, old_folder, '*@*', self.appid)

            for entry in entry_list.items():
                key = entry[0]
                password = entry[1]

                username, service = key.rsplit('@', 1)
                ret = self.iface.writePassword(
                    self.handle, service, username, password, self.appid)
                if ret == 0:
                    self.iface.removeEntry(
                        self.handle, old_folder, key, self.appid)

            entry_list = self.iface.readPasswordList(
                self.handle, old_folder, '*', self.appid)
            if not entry_list:
                self.iface.removeFolder(self.handle, old_folder, self.appid)

    def connected(self, service):
        if self.handle >= 0:
            return True
        bus = dbus.SessionBus(mainloop=DBusGMainLoop())
        wId = 0
        try:
            remote_obj = bus.get_object(self.bus_name, self.object_path)
            self.iface = dbus.Interface(remote_obj, 'org.kde.KWallet')
            self.handle = self.iface.open(
                self.iface.networkWallet(), wId, self.appid)
        except dbus.DBusException:
            self.handle = -1
        if self.handle < 0:
            return False
        self._migrate(service)
        return True

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        if not self.connected(service):
            # the user pressed "cancel" when prompted to unlock their keyring.
            return None
        if not self.iface.hasEntry(self.handle, service, username, self.appid):
            return None
        password = self.iface.readPassword(
            self.handle, service, username, self.appid)
        return str(password)

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        if not self.connected(service):
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordSetError("Cancelled by user")
        self.iface.writePassword(
            self.handle, service, username, password, self.appid)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        if not self.connected(service):
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordDeleteError("Cancelled by user")
        if not self.iface.hasEntry(self.handle, service, username, self.appid):
            raise PasswordDeleteError("Password not found")
        self.iface.removeEntry(self.handle, service, username, self.appid)


class DBusKeyringKWallet4(DBusKeyring):
    """
    KDE KWallet 4 via D-Bus
    """

    bus_name = 'org.kde.kwalletd'
    object_path = '/modules/kwalletd'

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        return super(DBusKeyringKWallet4, cls).priority - 1
