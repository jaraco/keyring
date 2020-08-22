import sys
import subprocess

import pytest


argv_manipulations = [
    'del sys.argv',
    'sys.argv = []',
    'sys.argv = None',
]


@pytest.mark.xfail(reason="#445")
@pytest.mark.parametrize('argv', argv_manipulations)
def test_argv(argv):
    code = f'import sys; {argv}; import keyring'
    cmd = [sys.executable, '-c', code]
    assert not subprocess.check_output(cmd, stderr=subprocess.STDOUT)
