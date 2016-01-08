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

    @classmethod
    def check_requisite_vars(cls):
        """
        Raise RuntimeError if the requisite vars aren't present.
        """
        if not cls.has_requisite_vars():
            raise RuntimeError("Requisite environment vars are not present")
