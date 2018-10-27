import os
import abc
import collections

from .py27compat import add_metaclass

__metaclass__ = type


@add_metaclass(abc.ABCMeta)
class Credential:
    """Abstract class to manage credentials
    """

    @abc.abstractproperty
    def username(self):
        return None

    @abc.abstractproperty
    def password(self):
        return None


class SimpleCredential(
        collections.namedtuple('Credential', 'username password'),
        Credential):
    """Simple credentials implementation
    """


class EnvironCredential(Credential):
    """Source credentials from environment variables.
       Actual sourcing is deferred until requested.
    """

    def __init__(self, user_env_var, pwd_env_var):
        self.user_env_var = user_env_var
        self.pwd_env_var = pwd_env_var

    def _get_env(self, env_var):
        """Helper to read an environment variable
        """
        value = os.environ.get(env_var)
        if not value:
            raise ValueError('Missing environment variable:%s' % env_var)
        return value

    @property
    def username(self):
        return self._get_env(self.user_env_var)

    @property
    def password(self):
        return self._get_env(self.pwd_env_var)
