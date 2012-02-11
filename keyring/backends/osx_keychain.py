#!/usr/bin/python

import sys
import subprocess
import re
import binascii

if sys.platform != 'darwin':
    raise ImportError('Mac OS X only module')

def password_set(realmstring, username, password):
    if username is None:
        username = ''
    try:
        subprocess.check_output([
                'security',
                'add-generic-password',
                '-a',
                username,
                '-s',
                realmstring,
                '-w',
                password,
                '-U'
            ],
            stderr = subprocess.STDOUT
        )
    except:
        raise OSError("Can't store password in keychain")


def password_get(realmstring, username):
    if username is None:
        username = ''
    try:
        output = subprocess.check_output([
                'security',
                'find-generic-password',
                '-g',
                '-a',
                username,
                '-s',
                realmstring
            ],
            stderr=subprocess.STDOUT
        )
        print output.split('\n')[0]
        matches = re.search('password:(?P<hex>.*?)"(?P<pw>.*)"', output)
        if matches:
            hex = matches.group('hex').strip()
            pw = matches.group('pw')
            if hex:
                return binascii.unhexlify(hex[2:])
            else:
                return pw
        return ''
    except:
        raise OSError("Can't fetch password from system")
