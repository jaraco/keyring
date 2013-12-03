# Used by pyinstaller to expose hidden imports

# TODO: can this be loaded from keyring.backend directly?
_backend_mod_names = ('file', 'Gnome', 'Google', 'keyczar', 'kwallet', 'multi',
    'OS_X', 'pyfs', 'SecretService', 'Windows')

hiddenimports = [
    'keyring.backends.' + mod_name
    for mod_name in _backend_mod_names
]
