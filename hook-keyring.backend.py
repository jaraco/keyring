# Used by pyinstaller to expose hidden imports

import sys

if sys.version_info < (3, 8):
    import importlib_metadata as metadata
else:
    import importlib.metadata as metadata


hiddenimports = [ep.value for ep in metadata.entry_points(group='keyring.backends')]
