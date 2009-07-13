"""
keyring_demo.py

This demo shows how to create a new keyring and enable it in keyring lib.

Created by Kang Zhang on 2009-07-12
"""

import sys
import os

KEYRINGRC = ".keyringrc"

def load_keyring_by_config():
    """
    This function shows how to enable a keyring using config file
    """
    f = open(KEYRINGRC,'w')
    f.writelines(["[backend]\n",
                  "keyring-path= %s\n" % str(os.path.abspath(__file__))[:-16],
                  "default-keyring=simplekeyring.SimpleKeyring\n" ])
    f.close()

    import keyring

    if keyring.setpass("demo-service","tarek","passexample") == 0:
        print "password stored sucessful"

    print "password", keyring.getpass("demo-service","tarek")
    os.remove(KEYRINGRC)

def set_keyring_in_runtime():
    """
    This function shows how to create a keyring manully and use it in runtime
    """
    import keyring.backend
    class TestKeyring(keyring.backend.KeyringBackend):
        def setpass(self,servicename,username,password): return 0 
        def getpass(self,servicename,username): return "password from TestKeyring"
    
    import keyring
    keyring.set_keyring(TestKeyring())

    if keyring.setpass("demo-service","tarek","passexample") == 0:
        print "password stored successful"

    print "password", keyring.getpass("demo-service","tarek")

def main():
    """
    This script shows how to enable the keyring using the config file and
    in runtime. 
    """

    load_keyring_by_config()

    set_keyring_in_runtime()

if __name__ == '__main__':
    main()
