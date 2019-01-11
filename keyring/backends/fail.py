from ..backend import KeyringBackend


class Keyring(KeyringBackend):
    """
    Keyring that raises error on every operation.

    >>> kr = Keyring()
    >>> kr.get_password('svc', 'user')
    Traceback (most recent call last):
    ...
    RuntimeError: ...No recommended backend...
    """

    priority = 0

    def get_password(self, service, username, password=None):
        msg = (
            "No recommended backend was available.  Install a recommended 3rd "
            "party backend package; or, install the keyrings.alt package if "
            "you want to use the non-recommended backends. See README.rst "
            "( https://github.com/jaraco/keyring/blob/master/README.rst ) "
            "for details."
        )
        raise RuntimeError(msg)

    set_password = delete_password = get_password
