from pluggy import HookimplMarker

import keyring
from keyring.errors import KeyringError


hookimpl = HookimplMarker("devpiclient")


@hookimpl()
def devpiclient_get_password(url, username):
    try:
        return keyring.get_password(url, username)
    except KeyringError:
        return None
