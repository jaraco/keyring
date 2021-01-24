import platform

collect_ignore = ["hook-keyring.backend.py"]

if platform.system() != 'Darwin':
    collect_ignore.append('keyring/backends/macOS/api.py')

collect_ignore.append('keyring/devpi_client.py')
