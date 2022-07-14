import contextlib

from pluggy import HookimplMarker

import keyring
from keyring.errors import KeyringError


hookimpl = HookimplMarker("devpiclient")


@hookimpl()
def devpiclient_get_password(url, username):
    with contextlib.suppress(KeyringError):
        return keyring.get_password(url, username)
