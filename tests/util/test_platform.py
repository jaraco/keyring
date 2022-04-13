import pytest
import platform

from keyring.util.platform_ import (
    config_root,
    data_root,
    _config_root_Linux,
    _config_root_Windows,
    _data_root_Linux,
    _data_root_Windows,
)


@pytest.mark.skipif(
    platform.system() != "Linux", reason="Requires platform.system() == 'Linux'"
)
def test_platform_Linux():
    # rely on the Github Actions workflow to run this on different platforms

    assert config_root == _config_root_Linux
    assert data_root == _data_root_Linux


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Requires platform.system() == 'Windows'"
)
def test_platform_Windows():
    # rely on the Github Actions workflow to run this on different platforms

    assert config_root == _config_root_Windows
    assert data_root == _data_root_Windows
