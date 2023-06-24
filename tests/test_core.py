import keyring.core
from unittest.mock import patch
import pathlib
import tempfile


def test_init_recommended(monkeypatch):
    """
    Test filtering of backends to recommended ones (#117, #423).
    """
    monkeypatch.setattr(keyring.core, 'set_keyring', lambda kr: None)
    keyring.core.init_backend(keyring.core.recommended)


def test_load_config_missing(caplog):
    with tempfile.TemporaryDirectory() as tmpdirname:
        path = pathlib.Path(tmpdirname) / "keyringrc.cfg"
        with patch.object(
            keyring.core, '_config_path', return_value=path
        ) as config_path_mock:
            assert keyring.core.load_config() is None
            assert not caplog.records

        config_path_mock.assert_called_once()


def test_load_config_exists(caplog):
    with tempfile.TemporaryDirectory() as tmpdirname:
        path = pathlib.Path(tmpdirname) / "keyringrc.cfg"
        with open(path, "w", encoding='UTF-8') as file:
            file.write('[backend]\ndefault-keyring=keyring.backends.fail.Keyring\n')
        with patch.object(
            keyring.core, '_config_path', return_value=path
        ) as config_path_mock:
            assert keyring.core.load_config() is not None
            assert not caplog.records

        config_path_mock.assert_called_once()
