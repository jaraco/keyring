#!/usr/bin/python

import sys
import subprocess
import re

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
                '-a',
                username,
                '-s',
                realmstring,
                '-g'
            ],
            stderr=subprocess.STDOUT
        )
        matches = re.match('password: "(?P<pw>.*)"', output)
        if matches:
            return matches.group('pw')
        else:
            return ''
    except:
        raise OSError("Can't fetch password from system")
