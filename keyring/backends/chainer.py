"""
Keyring Chainer - iterates over other viable backends to
discover passwords in each.
"""

from __future__ import absolute_import

from .. import backend
from .. import core


class ChainerBackend(backend.KeyringBackend):
    """
    >>> ChainerBackend()
    <keyring.backends.chainer.ChainerBackend object at ...>
    """

    priority = 10

    @property
    def backends(self):
        """
        Discover all keyrings for chaining.
        """
        allowed = (
            keyring for keyring in backend.get_all_keyring()
            if keyring.priority > 0
            if not isinstance(keyring, ChainerBackend)
        )
        return sorted(allowed, key=core.by_priority, reverse=True)

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
