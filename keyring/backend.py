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


class FileKeyring(KeyringBackend):
    """FileKeyring is a pure python implementation of keyring. It 
    store the password directly in the file, so it's not safe.
    """
    def __init__(self):
        import os
        self.fp = os.path.join(os.getenv("HOME"),".keyring_password")

    def getpass(self,servicename,username):
        import os,ConfigParser
        # load the passwords from the file
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.fp): config.read(self.fp)

        # fetch the password
        password = None
        try:
            password = config.get(servicename,username)
        except Config.NoOptionError: pass
        return password

    def setpass(self,servicename,username,password):
        import os,ConfigParser
        # load the password from the disk
        config = ConfigParser.RawConfigParser()
        if os.path.exists(self.fp): config.read(self.fp)

        # write the modification
        if not config.has_section(servicename):
            config.add_section(servicename)
        config.set(servicename,username,password)
        f = open(self.fp,'w')
        config.write(f)
        if f: f.close()

        return 0
    
