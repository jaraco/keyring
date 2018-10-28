"""
Implementation of a keyring backend chainer.

This is specifically not a viable backend, and must be
instantiated directly with a list of ordered backends.
"""

from __future__ import absolute_import

from ..backend import KeyringBackend


class ChainerBackend(KeyringBackend):
    def __init__(self, backends):
        self.backends = list(backends)

    def get_password(self, service, username):
        for backend in self.backends:
            password = backend.get_password(service, username)
            if password is not None:
                return password

    def set_password(self, service, username, password):
        for backend in self.backends:
            try:
                return backend.set_password(service, username, password)
            except NotImplementedError:
                pass

    def delete_password(self, service, username):
        for backend in self.backends:
            try:
                return backend.delete_password(service, username)
            except NotImplementedError:
                pass

    def get_credential(self, service, username):
        for backend in self.backends:
            credential = backend.get_credential(service, username)
            if credential is not None:
                return credential
