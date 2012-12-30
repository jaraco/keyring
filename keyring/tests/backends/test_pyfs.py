import os
import tempfile
import platform

from ..py30compat import unittest

import keyring.backend
from ..test_backend import BackendBasicTests, random_string

def is_pyfilesystem_supported():
    try:
        __import__('fs.opener')
    except ImportError:
        return False
    return True

# Due to a `bug <https://bitbucket.org/kang/python-keyring-lib/issue/78>`_
# in our usage of pyfilesystem, the tests fail on Windows, so mark them as
# such.
xfail_win = (unittest.expectedFailure
    if platform.system() == 'Windows' else lambda func: func)

class ReverseCrypter(keyring.backend.Crypter):
    """Very silly crypter class"""

    def encrypt(self, value):
        return value[::-1]

    def decrypt(self, value):
        return value[::-1]

class PyfilesystemKeyringTests(BackendBasicTests):
    """Base class for Pyfilesystem tests"""

    def setUp(self):
        super(PyfilesystemKeyringTests, self).setUp()
        self.keyring = self.init_keyring()

    def tearDown(self):
        del self.keyring

    def test_encrypt_decrypt(self):
        password = random_string(20)
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedMemoryPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test in memory with no encryption"""

    keyring_filename = 'mem://unencrypted'

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedMemoryPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test in memory with no encryption"""

    keyring_filename = 'mem://some/sub/dir/unencrypted'

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedLocalPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with no encryption"""

    keyring_filename = '%s/keyring.cfg' %tempfile.mkdtemp()

    def init_keyring(self):
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

    def test_handles_preexisting_keyring(self):
        from fs.opener import opener
        fs, path = opener.parse(self.keyring_filename, writeable=True)
        keyring_file = fs.open(path, 'wb')
        keyring_file.write(
            """[svc1]
user1 = cHdkMQ==
            """)
        keyring_file.close()
        pyf_keyring = keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)
        self.assertEquals('pwd1', pyf_keyring.get_password('svc1', 'user1'))

    def tearDown(self):
        del self.keyring
        if os.path.exists(self.keyring_filename):
            os.remove(self.keyring_filename)

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class UnencryptedLocalPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with no encryption"""

    keyring_dir = '%s//more/sub/dirs' %tempfile.mkdtemp()
    keyring_filename = '%s/keyring.cfg' %keyring_dir

    def init_keyring(self):

        if not os.path.exists(self.keyring_dir):
            os.makedirs(self.keyring_dir)
        return keyring.backend.UnencryptedPyfilesystemKeyring(
            filename=self.keyring_filename)

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedMemoryPyfilesystemKeyringTestCase(PyfilesystemKeyringTests,
                                                 unittest.TestCase):
    """Test in memory with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='mem://encrypted/keyring.cfg')

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedLocalPyfilesystemKeyringNoSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='temp://keyring.cfg')

@xfail_win
@unittest.skipUnless(is_pyfilesystem_supported(),
                     "Need Pyfilesystem")
class EncryptedLocalPyfilesystemKeyringSubDirTestCase(
    PyfilesystemKeyringTests,
    unittest.TestCase):
    """Test using local temp files with encryption"""

    def init_keyring(self):
        return keyring.backend.EncryptedPyfilesystemKeyring(
            ReverseCrypter(),
            filename='temp://a/sub/dir/hierarchy/keyring.cfg')
