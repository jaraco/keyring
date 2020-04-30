try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata


def test_entry_point():
    """
    Keyring provides exactly one 'keyring' console script
    that's a callable.
    """
    scripts = dict(metadata.entry_points()['console_scripts'])
    assert callable(scripts['keyring'].load())
