"""Specific support for getpass."""
import os
import getpass

from keyring.core import get_password as original_get_password

def get_password(prompt='Password: ', stream=None,
                 service_name='Python',
                 username=None):
    if username is None:
        username = getpass.getuser()
    return original_get_password(service_name, username)

