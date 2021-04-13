import sys

if sys.version_info < (3, 8):
    import importlib_metadata as metadata
else:
    import importlib.metadata as metadata

from keyring import backend


def test_entry_point():
    """
    Keyring provides exactly one 'keyring' console script
    that's a callable.
    """
    if sys.version_info < (3, 8):
        matches = metadata.entry_points(group='console_scripts', name='keyring')
    else:
        scripts = metadata.entry_points()['console_scripts']
        matches = tuple([ep for ep in scripts if ep.name == 'keyring'])
        print(matches) # TODO: remove, this is just to verify why tests are failing
    (script,) = matches
    assert callable(script.load())


def test_missing_metadata(monkeypatch):
    """
    _load_plugins should pass when keyring metadata is missing.
    """
    if sys.version_info < (3, 8):
        monkeypatch.setattr(metadata, 'entry_points', metadata.EntryPoints().select)
    backend._load_plugins()
