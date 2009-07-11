from abc import ABCMeta,abstractmethod

class KeyringBackend():
    __metaclass__ = ABCMeta

    @abstractmethod
    def getpass(self,servicename,username): pass
    @abstractmethod
    def setpass(self,servicename,username,password): pass

class _ExtensionKeyring(KeyringBackend):
    def __init__(self):
        self.keyring_impl = self._init_backend()

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


