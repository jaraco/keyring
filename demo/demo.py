#!/usr/bin/env python
# encoding: utf-8
"""
demo.py

Created by Kang Zhang on 2009-06-13.
"""

import keyring


def main():
    """This script demos the python keyring lib usage. To see the 
    changes that keyring lib has made on your machine, open your 
    Keychain Access and search for demo-service in your login 
    keychain.
    """
    if keyring.set_password("demo-service", "tarek", "passexample") == 0:
        print "password stored sucessful"
        
    print keyring.get_password("demo-service", "tarek")


if __name__ == '__main__':
    main()

