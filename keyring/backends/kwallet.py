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
    """KDE KWallet via D-Bus
       find out, which kwallet is in use with the wallet class attribute:

       --> import keyring
       --> kr = keyring.get_keyring()
       --> kr
       <keyring.backends.kwallet.DBusKeyring object at 0x7fac597492b0>

       kwallet
       --> kr.wallet.requested_bus_name
       'org.kde.kwalletd'
       --> kr.wallet.object_path
       '/modules/kwalletd'

       kwallet5
       --> kr.wallet.requested_bus_name
       'org.kde.kwalletd5'
       --> kr.wallet.object_path
       '/modules/kwalletd5'
    """

    appid = 'Python program'
    wallet = None

    # wallet objects, ordered by internal priority
    _wallet_objects = [
        # KWallet5
        ('org.kde.kwalletd5', '/modules/kwalletd5'),
        # KWallet
        ('org.kde.kwalletd', '/modules/kwalletd'),
    ]

    @classmethod
    def _select_wallet(cls, bus):
        if cls.wallet is not None:
            return cls.wallet

        for bus_name, object_path in cls._wallet_objects:
            try:
                proxy = bus.get_object(bus_name, object_path)
            except dbus.DBusException:
                pass
            else:
                cls.wallet = proxy
                return proxy

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        if 'dbus' not in globals():
            raise RuntimeError('python-dbus not installed')
        try:
            bus = dbus.SessionBus()
        except dbus.DBusException as exc:
            raise RuntimeError(exc.get_dbus_message())
        if cls._select_wallet(bus) is None:
            raise RuntimeError('cannot connect to org.kde.kwalletd{4,5}')
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
                    self.iface.removeEntry(self.handle, old_folder, key, self.appid)

            entry_list = self.iface.readPasswordList(
                    self.handle, old_folder, '*', self.appid)
            if not entry_list:
                self.iface.removeFolder(self.handle, old_folder, self.appid)

    def connected(self, service):
        if self.handle >= 0:
            return True
        bus = dbus.SessionBus()
        wId = 0
        try:
            self.iface = dbus.Interface(self.wallet, 'org.kde.KWallet')
        except dbus.DBusException:
            # oops, invalid dbus session, try to reconnect
            DBusKeyring._select_wallet(bus)
            try:
                self.iface = dbus.Interface(self.wallet, 'org.kde.KWallet')
            except dbus.DBusException:
                # we're in serious touble now, give up
                return False
        try:
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
