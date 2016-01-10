from __future__ import absolute_import

import os
import sys

from ..py27compat import unicode_str
from ..backend import KeyringBackend
from ..errors import PasswordDeleteError
from ..errors import PasswordSetError, ExceptionRaisedContext
from ..util import properties

# mixing Qt4 & Qt5 causes errors and may segfault
if 'PyQt5' not in sys.modules:
    try:
        from PyKDE4.kdeui import KWallet
        from PyQt4 import QtGui
    except ImportError:
        pass

try:
    import dbus
except ImportError:
    pass

kwallet = None

def open_kwallet(kwallet_module=None, qt_module=None):

    # If we specified the kwallet_module and/or qt_module, surely we won't need
    # the cached kwallet object...
    if kwallet_module is None and qt_module is None:
        global kwallet
        if not kwallet is None:
            return kwallet

    # Allow for the injection of module-like objects for testing purposes.
    if kwallet_module is None:
        kwallet_module = KWallet.Wallet
    if qt_module is None:
        qt_module = QtGui

    # KDE wants us to instantiate an application object.
    app = None
    if qt_module.qApp.instance() == None:
        app = qt_module.QApplication([])
    try:
        window = qt_module.QWidget()
        kwallet = kwallet_module.openWallet(
            kwallet_module.NetworkWallet(),
            window.winId(),
            kwallet_module.Synchronous)
        if kwallet is not None:
            if not kwallet.hasFolder('Python'):
                kwallet.createFolder('Python')
            kwallet.setFolder('Python')
            return kwallet
    finally:
        if app:
            app.exit()

class QtKeyring(KeyringBackend):
    """KDE KWallet"""

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        with ExceptionRaisedContext() as exc:
            KWallet.__name__
        if exc:
            raise RuntimeError("KDE libraries not available")
        if "DISPLAY" not in os.environ:
            raise RuntimeError("cannot connect to X server")
        # Infer if KDE environment is active based on environment vars.
        # TODO: Does PyKDE provide a better indicator?
        kde_session_keys = (
            'KDE_SESSION_ID', # most environments
            'KDE_FULL_SESSION', # openSUSE
        )
        if not set(os.environ).intersection(kde_session_keys):
            return 0
        return 5

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        key = username + '@' + service
        network = KWallet.Wallet.NetworkWallet()
        wallet = open_kwallet()
        if wallet is None:
            # the user pressed "cancel" when prompted to unlock their keyring.
            return None
        if wallet.keyDoesNotExist(network, 'Python', key):
            return None

        result = wallet.readPassword(key)[1]
        # The string will be a PyQt4.QtCore.QString, so turn it into a unicode
        # object.
        return unicode_str(result)

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        wallet = open_kwallet()
        if wallet is None:
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordSetError("Cancelled by user")
        wallet.writePassword(username+'@'+service, password)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        key = username + '@' + service
        wallet = open_kwallet()
        if wallet is None:
            # the user pressed "cancel" when prompted to unlock their keyring.
            raise PasswordDeleteError("Cancelled by user")
        if wallet.keyDoesNotExist(wallet.walletName(), 'Python', key):
            raise PasswordDeleteError("Password not found")
        wallet.removeEntry(key)


class DBusKeyring(KeyringBackend):
    """KDE KWallet via D-Bus"""

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
            bus.get_object('org.kde.kwalletd', '/modules/kwalletd')
        except dbus.DBusException:
            raise RuntimeError('cannot connect to org.kde.kwalletd')
        return 5.1

    def __init__(self, *arg, **kw):
        super(DBusKeyring, self).__init__(*arg, **kw)
        self.handle = -1

    def connected(self):
        if self.handle >= 0:
            return True
        bus = dbus.SessionBus()
        wId = 0
        self.folder = 'Python'
        self.appid = 'Python program'
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


# for backward compatibility
Keyring = QtKeyring
