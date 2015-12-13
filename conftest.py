import platform

collect_ignore = [
	"hook-keyring.backend.py",
]

if platform.system() != 'Windows':
	collect_ignore.append('keyring/backends/_win_crypto.py')
