try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata

from keyring import backend


def test_entry_point():
    """
    Keyring provides exactly one 'keyring' console script
    that's a callable.
    """
    scripts = dict(metadata.entry_points()['console_scripts'])
    assert callable(scripts['keyring'].load())


def test_missing_metadata(monkeypatch):
    """
    _load_plugins should pass when keyring metadata is missing.
    """
    monkeypatch.setattr(metadata, 'entry_points', dict)
    backend._load_plugins()
