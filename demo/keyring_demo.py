"""
keyring_demo.py

This demo shows how to create a new keyring and enable it in keyring lib.

Created by Kang Zhang on 2009-07-12
"""

import sys
import os

KEYRINGRC = ".keyringrc"

def load_keyring_by_config():
    """This function shows how to enable a keyring using config file
    """

    # create the config file
    f = open(KEYRINGRC,'w')
    f.writelines(["[backend]\n",
                  # the path for the user created keyring
                  "keyring-path= %s\n" % str(os.path.abspath(__file__))[:-16],
                  # the name of the keyring class 
                  "default-keyring=simplekeyring.SimpleKeyring\n" ])
    f.close()

    # import the keyring lib, the lib will automaticlly load the
    # config file and load the user defined module
    import keyring

    # invoke the keyring to store and fetch the password
    if keyring.setpass("demo-service","tarek","passexample") == 0:
        print "password stored sucessful"
    print "password", keyring.getpass("demo-service","tarek")

    os.remove(KEYRINGRC)

def set_keyring_in_runtime():
    """This function shows how to create a keyring manully and use it 
    in runtime
    """

    # define a new keyring class which extends the KeyringBackend
    import keyring.backend
    class TestKeyring(keyring.backend.KeyringBackend):
        def supported(self): return 0
        def setpass(self,servicename,username,password): return 0 
        def getpass(self,servicename,username): 
            return "password from TestKeyring"
    
    # set the keyring for keyring lib
    import keyring
    keyring.set_keyring(TestKeyring())

    # invoke the keyring lib
    if keyring.setpass("demo-service","tarek","passexample") == 0:
        print "password stored successful"
    print "password", keyring.getpass("demo-service","tarek")

def main():
    """This script shows how to enable the keyring using the config 
    file and in runtime. 
    """

    load_keyring_by_config()

    set_keyring_in_runtime()

if __name__ == '__main__':
    main()
