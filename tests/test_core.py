import keyring.core


def test_init_recommended(monkeypatch):
    """
    Test filtering of backends to recommended ones (#117, #423).
    """
    monkeypatch.setattr(keyring.core, 'set_keyring', lambda kr: None)
    keyring.core.init_backend(keyring.core.recommended)


def test_load_config_missing(caplog):
    assert keyring.core.load_config() is None
    assert not caplog.records
