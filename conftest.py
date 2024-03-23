import platform


not_macOS = platform.system() != 'Darwin'

collect_ignore = ["hook-keyring.backend.py"] + [
    'keyring/backends/macOS/api.py'
] * not_macOS
