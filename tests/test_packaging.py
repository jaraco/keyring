import importlib_metadata as metadata

from keyring import backend


def test_entry_point():
    """
    Keyring provides exactly one 'keyring' console script
    that's a callable.
    """
    matches = metadata.entry_points(group='console_scripts', name='keyring')
    (script,) = matches
    assert callable(script.load())


def test_missing_metadata(monkeypatch):
    """
    _load_plugins should pass when keyring metadata is missing.
    """
    monkeypatch.setattr(metadata, 'entry_points', metadata.EntryPoints().select)
    backend._load_plugins()
