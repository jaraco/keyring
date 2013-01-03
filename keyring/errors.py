class PasswordSetError(Exception):
    """Raised when the password can't be set.
    """

class PasswordDeleteError(Exception):
    """Raised when the password can't be deleted.
    """

class InitError(Exception):
    """Raised when the keyring could not be initialised
    """
