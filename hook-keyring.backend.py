# Used by pyinstaller to expose hidden imports

# TODO: can this be loaded from keyring.backend directly?
_backend_mod_names = 'kwallet', 'OS_X', 'SecretService', 'Windows'

hiddenimports = [
    'keyring.backends.' + mod_name
    for mod_name in _backend_mod_names
]
