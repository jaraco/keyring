"""Specific support for getpass."""
import os
import getpass

from keyring.core import get_password as original_get_password

get_default_user = getpass.getuser

def get_password(prompt='Password: ', stream=None,
                           service_name='Python',
                           username=get_default_user()):
    return original_get_password(service_name, username)

