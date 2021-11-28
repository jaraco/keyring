import ctypes

collect_ignore = ["hook-keyring.backend.py"]


def macos_api_ignore():
    """
    Starting with macOS 11, the security API becomes
    non-viable except on universal2 binaries.

    Ref #525.
    """

    try:
        ctypes.CDLL(ctypes.util.find_library('Security')).SecItemAdd
        return False
    except Exception:
        return True


collect_ignore.extend(['keyring/backends/macOS/api.py'] * macos_api_ignore())

collect_ignore.append('keyring/devpi_client.py')
