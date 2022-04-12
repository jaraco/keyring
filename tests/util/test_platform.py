import platform

from keyring.util.platform_ import (
    config_root,
    data_root,
    _config_root_Linux,
    _config_root_Windows,
    _data_root_Linux,
    _data_root_Windows,
)


def test_platform_Linux():
    # rely on the Github Actions workflow to run this on different platforms
    if platform.system() != "Linux":
        return

    assert config_root == _config_root_Linux
    assert data_root == _data_root_Linux


def test_platform_Windows():
    # rely on the Github Actions workflow to run this on different platforms
    if platform.system() != "Windows":
        return

    assert config_root == _config_root_Windows
    assert data_root == _data_root_Windows
