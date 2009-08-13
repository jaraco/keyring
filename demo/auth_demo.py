"""
auth_demo.py

Created by Kang Zhang 2009-08-14
"""

import keyring
import getpass
import ConfigParser

def auth(username, password):
    """A faked authorization function.
    """
    return username == password

def main():
    """This scrip demos how to use keyring facilite the authorization. The 
    username is stored in a config named 'auth_demo.cfg'
    """

    config_file = 'auth_demo.cfg'
    config = ConfigParser.SafeConfigParser({
                'username':'',
                })
    config.read(config_file)
    if not config.has_section('auth_demo_login'):
        config.add_section('auth_demo_login')

    username = config.get('auth_demo_login','username')
    password = None
    if username != '':
        password = keyring.get_password('auth_demo_login', username)

    if password == None or not auth(username, password):

        while 1:
            username = raw_input("Username:\n")
            password = getpass.getpass("Password:\n")

            if auth(username, password):
                break
            else:
                print "Authorization failed."
        
        # store the username
        config.set('auth_demo_login', 'username', username)
        config.write(open(config_file, 'w'))

        # store the password
        keyring.set_password('auth_demo_login', username, password)

    # the stuff that needs authorization here
    print "Authorization successful."

if __name__ == "__main__":
    main()
