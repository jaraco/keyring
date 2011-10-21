#!/usr/bin/env python
"""Simple command line interface to get/set password from a keyring"""

import getpass
import optparse
import sys

import keyring
import keyring.core


def input_password(prompt):
    """Ask for a password to the user.

    This mostly exists to ease the testing process.
    """

    return getpass.getpass(prompt)


def output_password(password):
    """Output the password to the user.

    This mostly exists to ease the testing process.
    """

    print password


def main(argv=None):
    """Main command line interface."""

    parser = optparse.OptionParser(usage="%prog [get|set] SERVICE USERNAME")
    parser.add_option("-p", "--keyring-path", dest="keyring_path", default=None,
                      help="Path to the keyring backend")
    parser.add_option("-b", "--keyring-backend", dest="keyring_backend", default=None,
                      help="Name of the keyring backend")

    if argv is None:
        argv = sys.argv[1:]

    opts, args = parser.parse_args(argv)

    try:
        kind, service, username = args
    except ValueError:
        if len(args) == 0:
            # Be nice with the user if he just tries to launch the tool
            parser.print_help()
            return 1
        else:
            parser.error("Wrong number of arguments")

    if opts.keyring_backend is not None:
        try:
            backend = keyring.core.load_keyring(opts.keyring_path, opts.keyring_backend)
            keyring.set_keyring(backend)
        except Exception, e:
            # Tons of things can go wrong here:
            #   ImportError when using "fjkljfljkl"
            #   AttributeError when using "os.path.bar"
            #   TypeError when using "__builtins__.str"
            # So, we play on the safe side, and catch everything.
            parser.error("Unable to load specified keyring: %s" % e)


    if kind == 'get':
        password = keyring.get_password(service, username)
        if password is None:
            return 1

        output_password(password)
        return 0

    elif kind == 'set':
        password = input_password("Password for '%s' in '%s': " %
                                  (username, service))
        keyring.set_password(service, username, password)
        return 0

    else:
        parser.error("You can only 'get' or 'set' a password.")


if __name__ == '__main__':
    sys.exit(main())
