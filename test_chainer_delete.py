import pytest

from keyring.backends import fail
from keyring.backends.chainer import ChainerBackend
from keyring import backend as backend_mod


class _LowBackend(fail.Keyring):
    priority = 1.0

    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


class _HighBackend(fail.Keyring):
    priority = 5.0

    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


@pytest.fixture
def chain():
    low, high = _LowBackend(), _HighBackend()
    ChainerBackend.backends = property(lambda cls: [high, low])
    backend_mod._limit = None
    yield ChainerBackend()
    ChainerBackend.backends = ChainerBackend.__dict__["backends"]


def test_delete_removes_from_lower_priority_backend(chain):
    """Regression test for jaraco/keyring#697.

    A password stored only in a lower-priority backend must be fully removed
    when deleted through the ChainerBackend, not left retrievable.
    """
    low = chain.backends[1]  # lower priority
    low.set_password("svc", "user", "stale-secret")
    assert chain.get_password("svc", "user") == "stale-secret"

    chain.delete_password("svc", "user")

    assert chain.get_password("svc", "user") is None
