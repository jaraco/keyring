# Used by pyinstaller to expose hidden imports

import entrypoints


hiddenimports = [
    ep.module_name
    for ep in entrypoints.get_group_all('keyring.backends')
]
