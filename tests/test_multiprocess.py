import multiprocessing
import platform

import pytest

import keyring
from keyring.backends import fail


@pytest.fixture(autouse=True)
def workaround_pytest_12178(monkeypatch):
    """
    Ensure the current directory is on sys.path so that `tests` is importable.

    Workaround for #673.
    """
    monkeypatch.syspath_prepend('.')


def subprocess_get():
    keyring.get_password('test_app', 'test_user')


def _has_usable_keyring():
    """True when a non-fail backend is selected (see #737)."""
    try:
        return not isinstance(keyring.get_keyring(), fail.Keyring)
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(
        not _has_usable_keyring(),
        reason=(
            "no usable keyring backend available; install a recommended "
            "backend or keyrings.alt (#737)"
        ),
    ),
    pytest.mark.xfail(
        platform.system() == 'Linux',
        reason="#410: keyring discovery fails intermittently",
    ),
]


def test_multiprocess_get():
    proc1 = multiprocessing.Process(target=subprocess_get)
    proc1.start()
    proc1.join()
    assert proc1.exitcode == 0


def test_multiprocess_get_after_native_get():
    keyring.get_password('test_app', 'test_user')
    test_multiprocess_get()
