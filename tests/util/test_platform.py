import pytest

from keyring.util import platform_


@pytest.mark.skipif('platform.system() != "Linux"')
def test_platform_Linux():
    assert platform_.config_root == platform_._config_root_Linux
    assert platform_.data_root == platform_._data_root_Linux


@pytest.mark.skipif('platform.system() != "Windows"')
def test_platform_Windows():
    assert platform_.config_root == platform_._config_root_Windows
    assert platform_.data_root == platform_._data_root_Windows
