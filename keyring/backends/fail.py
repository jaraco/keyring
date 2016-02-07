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
        raise RuntimeError("No recommended backend was available. Install the "
                           "keyrings.alt package if you want to use the non-"
                           "recommended backends. See README.rst for details.")

    set_password = delete_pasword = get_password
