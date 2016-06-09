# Used by pyinstaller to expose hidden imports

# TODO: can this be loaded from keyring.backend directly?
_backend_mod_names = 'kwallet', 'OS_X', 'SecretService', 'Windows'

hiddenimports = [
    'keyring.backends.' + mod_name
    for mod_name in _backend_mod_names
]

import pkg_resources

hiddenimports.extend(
	ep.module_name
	for ep in pkg_resources.iter_entry_points('keyring.backends')
)
