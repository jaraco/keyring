import multiprocessing
import platform

import pytest

import keyring


@pytest.fixture(autouse=True)
def workaround_pytest_12178(monkeypatch):
    """
    Ensure the current directory is on sys.path so that `tests` is importable.

    Workaround for #673.
    """
    monkeypatch.syspath_prepend('.')


def subprocess_get():
    keyring.get_password('test_app', 'test_user')


pytestmark = [
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
