# Used by pyinstaller to expose hidden imports
import sys

if sys.version_info >= (3, 10):
    from importlib import metadata
else:
    import importlib_metadata as metadata #type: ignore

hiddenimports = [ep.value for ep in metadata.entry_points(group='keyring.backends')]
