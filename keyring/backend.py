"""
backend.py

Created by Kang Zhang on 2009-07-09
"""
from abc import ABCMeta, abstractmethod

class KeyringBackend():
    """The abstract base class of the keyring, every backend must implement
    this interface.
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
    def get_password(self, service, username): 
        """Get password of the username for the service
        """
        pass

    @abstractmethod
    def set_password(self, service, username, password): 
        """Set password for the username of the service
        """
        return -1

class _ExtensionKeyring(KeyringBackend):
    """_ExtensionKeyring is a adaptor class for the platform related keyring 
    backends.
    """
    def __init__(self):
        try:
            self.keyring_impl = self._init_backend()
        except ImportError:
            # keyring is not installed properly
            self.keyring_impl = None

    @abstractmethod
    def _init_backend(self):
        """Return the keyring implementation handler
        """
        return None
    
    @abstractmethod
    def _recommend(self):
        """If this keyring is recommanded on current enviroment.
        """
        return False

    def supported(self):
        """Override the supported() in KeyringBackend.
        """
        if self.keyring_impl is None:
            return -1
        elif self._recommend():
            return 1
        return 0 

    def get_password(self, service, username):
        """Override the get_password() in KeyringBackend.
        """
        return self.keyring_impl.password_get(service, username)

    def set_password(self, service, username, password):
        """Overide the set_password() in KeyringBackend.
        """
        return self.keyring_impl.password_set(service, username, password)
 
class OSXKeychain(_ExtensionKeyring):
    """The keyring backend based on Keychain Service of the Mac OSX
    """
    def _init_backend(self):
        """Return the handler: osx_keychain
        """
        import osx_keychain
        return osx_keychain

    def _recommend(self):
        """Recommend for all OSX enviroment.
        """
        import sys
        return sys.platform in ['darwin', 'mac'] 

class GnomeKeyring(_ExtensionKeyring):
    """The keyring backend using Gnome Keyring.
    """
    def _init_backend(self):
        """Return the gnome_keyring handler.
        """
        import gnome_keyring
        return gnome_keyring

    def _recommend(self):
        """Recommend this keyring when Gnome is running.
        """
        import os
        # Gnome is running 
        return os.getenv("GNOME_DESKTOP_SESSION_ID") is not None

      
class KDEKWallet(_ExtensionKeyring):
    """The keyring backend based on KDE KWallet
    """
    def _init_backend(self):
        """Return the kde_kwallet handler.
        """
        import kde_kwallet
        return kde_kwallet
 
    def _recommend(self):
        """Recommend this keyring backend when KDE is running.
        """
        import os
        # KDE is running 
        return os.getenv("KDE_FULL_SESSION") == "true"

class FileKeyring(KeyringBackend):
    """FileKeyring is a pure python implementation of keyring. It 
    store the password directly in the file, so it's not safe.
    """
    def __init__(self):
        import os
        self.file_path = os.path.join(os.getenv("HOME"),".keyring_password")

    def supported(self):
        """Applicable for all platform, but do not recommend.
        """
        return 0 

    def get_password(self, service, username):
        """Read the password from the file.
        """
        import os, ConfigParser
        # load the passwords from the file
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path): 
            config.read(self.file_path)

        # fetch the password
        try:
            password = config.get(service, username)
        except ConfigParser.NoOptionError: 
            password = None
        return password

    def set_password(self, service, username, password):
        """Write the password in the file
        """
        import os, ConfigParser
        # load the password from the disk
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.file_path): 
            config.read(self.file_path)

        # write the modification
        if not config.has_section(service):
            config.add_section(service)
        config.set(service, username, password)
        config_file = open(self.file_path,'w')
        config.write(config_file)
        if config_file: 
            config_file.close()

        return 0

def get_all_keyring():
    """Return the list of all keyrings in the lib
    """
    return [ OSXKeychain(), GnomeKeyring(), KDEKWallet(), FileKeyring() ]

