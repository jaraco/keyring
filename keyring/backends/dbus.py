import os


class DBus(object):
    """
    Mix-in for backends relying on DBus.
    """

    requisite_vars = [
        'DISPLAY',
        'DBUS_SESSION_BUS_ADDRESS',
    ]

    @classmethod
    def has_requisite_vars(cls):
        """
        Return True if the requisite environment vars are present in the
        environment.
        """
        return set(cls.requisite_vars).issubset(os.environ)
