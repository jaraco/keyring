import pytest

import keyring.core
from keyring.backends.fail import Keyring
from keyring.errors import NoKeyringError


@pytest.mark.parametrize('username', [None, 'user'])
def test_get_credential_raises(username, monkeypatch):
    """
    The fail backend raises on every operation, so a caller must never be
    able to read the result of ``get_credential`` as "no such credential"
    when in fact no keyring backend is available.
    """
    monkeypatch.setattr(keyring.core, '_keyring_backend', Keyring())
    with pytest.raises(NoKeyringError):
        keyring.core.get_credential('svc', username)
