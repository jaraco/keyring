import pkg_resources


def test_entry_point():
    """
    Keyring provides exactly one 'keyring' console script
    that's a callable.
    """
    eps = pkg_resources.iter_entry_points('console_scripts')
    ep, = (
        ep
        for ep in eps
        if ep.name == 'keyring'
    )
    assert callable(ep.resolve())
