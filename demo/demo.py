#!/usr/bin/env python
# encoding: utf-8
"""
demo.py

Created by Kang Zhang on 2009-06-13.
"""

import keyring
import getpass

def main():
    """This script demos the python keyring lib api. To see the changes that 
    keyring lib has made on your machine, open your Keychain and search for 
    demo-service in your login keychain.
    """
    
    username = raw_input("Username for demo:\n")
    password = keyring.get_password("demo-service", username)
    
    print "Password fetched from the keyring: ", password

    password = getpass.getpass("Password:\n")
    keyring.set_password("demo-service", username, password)

if __name__ == '__main__':
    main()

