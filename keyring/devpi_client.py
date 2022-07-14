from pluggy import HookimplMarker
from jaraco.context import suppress

import keyring
from keyring.errors import KeyringError


hookimpl = HookimplMarker("devpiclient")


@hookimpl()
@suppress(KeyringError)
def devpiclient_get_password(url, username):
    return keyring.get_password(url, username)
