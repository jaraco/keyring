# Used by pyinstaller to expose hidden imports

import importlib_metadata as metadata


hiddenimports = [ep.value for ep in metadata.entry_points(group='keyring.backends')]
