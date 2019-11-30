# Used by pyinstaller to expose hidden imports

try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata


hiddenimports = [ep.value for ep in metadata.entry_points()['keyring.backends']]
