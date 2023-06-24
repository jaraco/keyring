import textwrap

import pytest

import keyring.core


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    path = tmp_path / 'keyringrc.cfg'
    monkeypatch.setattr(keyring.core, '_config_path', lambda: path)
    return path


def test_init_recommended(monkeypatch):
    """
    Test filtering of backends to recommended ones (#117, #423).
    """
    monkeypatch.setattr(keyring.core, 'set_keyring', lambda kr: None)
    keyring.core.init_backend(keyring.core.recommended)


def test_load_config_missing(caplog, config_path):
    assert keyring.core.load_config() is None
    assert not caplog.records


fail_config = textwrap.dedent(
    """
    [backend]
    default-keyring = keyring.backends.fail.Keyring
    """
).lstrip()


def test_load_config_extant(caplog, config_path):
    config_path.write_text(fail_config, encoding='utf-8')
    assert keyring.core.load_config() is not None
    assert not caplog.records
