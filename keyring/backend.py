"""
backend.py

Created by Kang Zhang on 2009-07-09
"""
from abc import ABCMeta,abstractmethod

class KeyringBackend():
    """The abstract base class of the keyring, every backend must
    implement this interface.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def supported(self):
        """Return if this keyring supports current enviroment.
        -1: not applicable
         0: suitable
         1: recommended
        """
        return -1

    @abstractmethod
    def getpass(self,service,username): 
        """Get password of the username for the service
        """
        pass

    @abstractmethod
    def setpass(self,service,username,password): 
        """Set password for the username of the service
        """
        return -1

class _ExtensionKeyring(KeyringBackend):
    def __init__(self):
        try:
            self.keyring_impl = self._init_backend()
        except ImportError:
            # keyring is not installed properly
            self.keyring_impl = None

    @abstractmethod
    def _init_backend(self):pass
    
    @abstractmethod
    def _recommend(self):
        return False

    def supported(self):
        if self.keyring_impl is None:
            return -1
        elif self._recommend():
            return 1
        return 0 

    def getpass(self,service,username):
        return self.keyring_impl.password_get(service,username)

    def setpass(self,service,username,password):
        return self.keyring_impl.password_set(service,username,password)
 
class OSXKeychain(_ExtensionKeyring):
    def _init_backend(self):
        import osx_keychain
        return osx_keychain

    def _recommend(self):
        import sys
        return sys.platform in ['darwin','mac'] 

class GnomeKeyring(_ExtensionKeyring):
    def _init_backend(self):
        import gnome_keyring
        return gnome_keyring

    def _recommend(self):
        import os
        # Gnome is running 
        return os.getenv("GNOME_DESKTOP_SESSION_ID") is not None

      
class KDEKWallet(_ExtensionKeyring):
    def _init_backend(self):
        import kde_kwallet
        return kde_kwallet
 
    def _recommend(self):
        import os
        # KDE is running 
        return os.getenv("KDE_FULL_SESSION") == "true"

class FileKeyring(KeyringBackend):
    """FileKeyring is a pure python implementation of keyring. It 
    store the password directly in the file, so it's not safe.
    """
    def __init__(self):
        import os
        self.fp = os.path.join(os.getenv("HOME"),".keyring_password")

    def supported(self):
        return 0 

    def getpass(self,service,username):
        import os,ConfigParser
        # load the passwords from the file
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.fp): config.read(self.fp)

        # fetch the password
        password = None
        try:
            password = config.get(service,username)
        except Config.NoOptionError: pass
        return password

    def setpass(self,service,username,password):
        import os,ConfigParser
        # load the password from the disk
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.fp): config.read(self.fp)

        # write the modification
        if not config.has_section(service):
            config.add_section(service)
        config.set(service,username,password)
        f = open(self.fp,'w')
        config.write(f)
        if f: f.close()

        return 0

def get_all_keyring():
    """Return the list of all keyrings in the lib
    """
    return [ OSXKeychain(), GnomeKeyring(), KDEKWallet(), FileKeyring() ]

