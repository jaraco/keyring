#!/usr/bin/env python

import getpass
import optparse
import sys

import keyring


def main():
    parser = optparse.OptionParser(usage="%prog [get|set] SERVICE USERNAME")
    opts, args = parser.parse_args()

    try:
        kind, service, username = args
    except ValueError:
        parser.error("Wrong number of arguments")

    if kind == 'get':
        password = keyring.get_password(service, username)
        if password is None:
            return 1

        print password
        return 0

    elif kind == 'set':
        password = getpass.getpass("Password for '%s' in '%s': " %
                                   (username, service))
        keyring.set_password(service, username, password)
        return 0

    else:
        parser.error("You can only 'get' or 'set' a password.")


if __name__ == '__main__':
    sys.exit(main())
