"""
simplekeyring.py

A simple keyring class for the keyring_demo.py

Created by Kang Zhang on 2009-07-12
"""
from keyring.backend import KeyringBackend

class SimpleKeyring(KeyringBackend):
    """Simple Keyring is a keyring which can store only one
    password in memory.
    """
    def __init__(self):
        self.password = ''
    def getpass(self,servicename,username):
        return self.password
    def setpass(self,servicename,username,password):
        print "calling SimpleKeyring.setpass()"
        self.password = password
        return 0 

