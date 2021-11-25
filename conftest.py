import sys
import platform

collect_ignore = ["hook-keyring.backend.py"]


def macos_api_ignore():
    """
    Starting with macOS 11, the security API becomes
    non-viable except on universal2 binaries.

    Ref #525.
    """

    def make_ver(string):
        return tuple(map(int, string.split('.')))

    release, _, _ = platform.mac_ver()

    return (
        platform.system() != 'Darwin'
        or make_ver(release) > (11,)
        and sys.version_info < (3, 8, 7)
    )


collect_ignore.extend(['keyring/backends/macOS/api.py'] * macos_api_ignore())

collect_ignore.append('keyring/devpi_client.py')
