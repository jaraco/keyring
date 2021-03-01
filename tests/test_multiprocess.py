import sys
import platform
import multiprocessing

import pytest

import keyring


def subprocess_get():
    keyring.get_password('test_app', 'test_user')


pytestmark = [
    pytest.mark.xfail(
        platform.system() == 'Linux',
        reason="#410: keyring discovery fails intermittently",
    ),
    pytest.mark.skipif(
        # always skip as it crashes the interpreter
        sys.version_info < (3, 8) and platform.system() == 'Darwin',
        reason="#281, #494: Prior to 3.8, multiprocess invocation fails",
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
