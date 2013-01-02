import contextlib
import os
import types
import sys

from ..py30compat import unittest
from ..test_backend import BackendBasicTests
from ..util import ImportKiller
from keyring.backends import Gnome

def is_gnomekeyring_supported():
    supported = Gnome.Keyring().supported()
    if supported == -1:
        return False
    return True

@contextlib.contextmanager
def NoNoneDictMutator(destination, **changes):
    """Helper context manager to make and unmake changes to a dict.

    A None is not a valid value for the destination, and so means that the
    associated name should be removed."""
    original = {}
    for key, value in changes.items():
        original[key] = destination.get(key)
        if value is None:
            if key in destination:
                del destination[key]
        else:
            destination[key] = value
    yield
    for key, value in original.items():
        if value is None:
            if key in destination:
                del destination[key]
        else:
            destination[key] = value


def Environ(**changes):
    """A context manager to temporarily change the os.environ"""
    return NoNoneDictMutator(os.environ, **changes)


def ImportBlesser(*names, **changes):
    """A context manager to temporarily make it possible to import a module"""
    for name in names:
        changes[name] = types.ModuleType(name)
    return NoNoneDictMutator(sys.modules, **changes)


@unittest.skipUnless(is_gnomekeyring_supported(),
                     "Need GnomeKeyring")
class GnomeKeyringTestCase(BackendBasicTests, unittest.TestCase):

    def environ(self):
        return dict(GNOME_KEYRING_CONTROL='1',
                    DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        k = Gnome.Keyring()

        # Store passwords in the session (in-memory) keyring for the tests. This
        # is going to be automatically cleared when the user logoff.
        k.KEYRING_NAME = 'session'

        return k

    def test_supported(self):
        with ImportBlesser('gnomekeyring'):
            with Environ(**self.environ()):
                self.assertEqual(1, self.keyring.supported())

    def test_supported_no_module(self):
        with ImportKiller('gnomekeyring'):
            with Environ(**self.environ()):
                self.assertEqual(-1, self.keyring.supported())

    def test_supported_no_keyring(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['GNOME_KEYRING_CONTROL'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())

    def test_supported_no_display(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['DISPLAY'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())

    def test_supported_no_session(self):
        with ImportBlesser('gnomekeyring'):
            environ = self.environ()
            environ['DBUS_SESSION_BUS_ADDRESS'] = None
            with Environ(**environ):
                self.assertEqual(0, self.keyring.supported())
