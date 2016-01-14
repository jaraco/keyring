from ..backend import KeyringBackend


class Keyring(KeyringBackend):
    """
    Keyring that raises error on every operation.

    >>> kr = Keyring()
    >>> kr.get_password('svc', 'user')
    Traceback (most recent call last):
    ...
    RuntimeError: ...
    """

    priority = 0

    def get_password(self, service, username, password=None):
        raise RuntimeError("No recommended password was available")

    set_password = delete_pasword = get_password
