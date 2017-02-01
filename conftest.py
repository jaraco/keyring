import platform

collect_ignore = [
    "hook-keyring.backend.py",
]

if platform.system() != 'Darwin':
	collect_ignore.append('keyring/backends/_OS_X_API.py')
