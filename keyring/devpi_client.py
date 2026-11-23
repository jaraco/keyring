import functools

import pluggy

import keyring.errors

from .compat import suppress

hookimpl = pluggy.HookimplMarker("devpiclient")


def restore_signature(func):
    # workaround for pytest-dev/pluggy#358
    @functools.wraps(func)
    def wrapper(url, username):
        return func(url, username)

    return wrapper


@hookimpl()
@restore_signature
@suppress(keyring.errors.KeyringError)
def devpiclient_get_password(url, username):
    """
    >>> pluggy._hooks.varnames(devpiclient_get_password)
    (('url', 'username'), ())
    >>>
    """
    return keyring.get_password(url, username)
