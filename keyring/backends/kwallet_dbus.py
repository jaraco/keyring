from __future__ import absolute_import

import os
import sys

try:
    import dbus
except ImportError:
    dbus = None

from ..backend import KeyringBackend
from ..errors import PasswordDeleteError
from ..errors import PasswordSetError
from ..util import properties
from ..util import XDG

class Keyring(KeyringBackend):
    """KDE KWallet via D-Bus"""

    @properties.ClassProperty
    @classmethod
    @XDG.Preference('KDE')
    def priority(cls):
        if not dbus:
            raise RuntimeError('python-dbus not installed')
        return 5.1

    def __init__(self, *arg, **kw):
        super(Keyring, self).__init__(*arg, **kw)
        self.handle = -1

    def connected(self):
        if self.handle >= 0:
            return True
        bus = dbus.SessionBus()
        wId = 0
        self.folder = 'Python'
        self.appid = 'Python program ' + sys.argv[0]
        try:
            remote_obj = bus.get_object('org.kde.kwalletd', '/modules/kwalletd')
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
