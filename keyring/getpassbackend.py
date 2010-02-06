"""Specific support for getpass."""
import os
import pwd

from keyring.core import get_password as original_get_password

def get_default_user():
    """Get the username from the environment or password database.

    First try various environment variables, then the password
    database.  This works on Windows as long as USERNAME is set.
    """
    for name in ('LOGNAME', 'USER', 'LNAME', 'USERNAME'):
        user = os.environ.get(name)
        if user:
            return user
    return pwd.getpwuid(os.getuid())[0]

def get_password(prompt='Password: ', stream=None,
                           service_name='Python',
                           username=get_default_user()):
    return original_get_password(service_name, username)

