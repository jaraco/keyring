"""
backend.py

Created by Kang Zhang on 2009-07-09
"""
from abc import ABCMeta,abstractmethod

class KeyringBackend():
    """
    The abstract base class of the keyring, every backend must
    implement this interface.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def getpass(self,servicename,username): pass
    @abstractmethod
    def setpass(self,servicename,username,password): pass

class _ExtensionKeyring(KeyringBackend):
    def __init__(self):
        try:
            self.keyring_impl = self._init_backend()
        except ImportError:
            print "Keyring does not installed properly"

    @abstractmethod
    def _init_backend(self):pass

    def getpass(self,servicename,username):
        return self.keyring_impl.password_get(servicename,username)
    def setpass(self,servicename,username,password):
        return self.keyring_impl.password_set(servicename,username,password)
 
class OSXKeychain(_ExtensionKeyring):
    def _init_backend(self):
        import osx_keychain
        return osx_keychain

class GnomeKeyring(_ExtensionKeyring):
    def _init_backend(self):
        import gnome_keyring
        return gnome_keyring
       
class KDEKWallet(_ExtensionKeyring):
    def _init_backend(self):
        import kde_kwallet
        return kde_kwallet


class SimpleKeyring(KeyringBackend):
    def getpass(self,servicename,username):
        return self.password
    
    def setpass(self,servicename,username,password):
        self.password = password
