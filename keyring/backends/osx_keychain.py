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
        # set up the call for security.
        call = subprocess.Popen([
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
            stderr = subprocess.PIPE,
            stdout = subprocess.PIPE,
        )
        code = call.wait()
        # check return code.
        if code is not 0:
            raise OSError('Can\'t store password in keychain')
    except:
        raise OSError("Can't store password in keychain")


def password_get(realmstring, username):
    if username is None:
        username = ''
    try:
        # set up the call to security.
        call = subprocess.Popen([
                'security',
                'find-generic-password',
                '-g',
                '-a',
                username,
                '-s',
                realmstring
            ],
            stderr = subprocess.PIPE,
            stdout = subprocess.PIPE,
        )
        code = call.wait()
        if code is not 0:
            raise OSError("Can't fetch password from system")
        output = call.stderr.readlines()[0]
        # check for empty password.
        if output == 'password: \n':
            return ''
        # search for special password pattern.
        matches = re.search('password:(?P<hex>.*?)"(?P<pw>.*)"', output)
        if matches:
            hex = matches.group('hex').strip()
            pw = matches.group('pw')
            if hex:
                # it's a weird hex password, decode it.
                return binascii.unhexlify(hex[2:])
            else:
                # it's a normal password, send it back.
                return pw
        # nothing was found, it doesn't exist.
        return None
    except:
        raise OSError("Can't fetch password from system")
