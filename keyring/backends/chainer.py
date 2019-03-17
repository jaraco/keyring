"""
Keyring Chainer - iterates over other viable backends to
discover passwords in each.
"""

from .. import backend
from ..util import properties


class ChainerBackend(backend.KeyringBackend):
    """
    >>> ChainerBackend()
    <keyring.backends.chainer.ChainerBackend object at ...>
    """

    # override viability as 'priority' cannot be determined
    # until other backends have been constructed
    viable = True

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        High-priority if there are backends to chain, otherwise 0.
        """
        return 10 * (len(cls.backends) > 1)

    @properties.ClassProperty
    @classmethod
    def backends(cls):
        """
        Discover all keyrings for chaining.
        """
        allowed = (
            keyring
            for keyring in filter(backend._limit, backend.get_all_keyring())
            if not isinstance(keyring, ChainerBackend)
            and keyring.priority > 0
        )
        return sorted(allowed, key=backend.by_priority, reverse=True)

    def get_password(self, service, username):
        for keyring in self.backends:
            password = keyring.get_password(service, username)
            if password is not None:
                return password

    def set_password(self, service, username, password):
        for keyring in self.backends:
            try:
                return keyring.set_password(service, username, password)
            except NotImplementedError:
                pass

    def delete_password(self, service, username):
        for keyring in self.backends:
            try:
                return keyring.delete_password(service, username)
            except NotImplementedError:
                pass

    def get_credential(self, service, username):
        for keyring in self.backends:
            credential = keyring.get_credential(service, username)
            if credential is not None:
                return credential
