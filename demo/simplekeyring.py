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

    def supported(self): 
        return 0

    def get_password(self, service, username):
        return self.password

    def set_password(self, service, username, password):
        self.password = password
        return 0 

