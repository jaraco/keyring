import sys
import subprocess

import pytest


argv_manipulations = [
    'del sys.argv',
    'sys.argv = []',
    'sys.argv = None',
]


@pytest.mark.parametrize('argv', argv_manipulations)
def test_argv(argv):
    """
    Keyrings should initialize without error even
    when sys.argv is malformed. Ref #445.
    """
    code = f'import sys; {argv}; import keyring'
    cmd = [sys.executable, '-c', code]
    assert not subprocess.check_output(cmd, stderr=subprocess.STDOUT)
