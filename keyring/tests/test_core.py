"""
test_core.py

Created by Kang Zhang on 2009-08-09
"""
import unittest
import os
import sys
import tempfile
import shutil
import subprocess

import keyring.backend
import keyring.core
import keyring.util.platform

PASSWORD_TEXT = "This is password"
PASSWORD_TEXT_2 = "This is password2"
KEYRINGRC = "keyringrc.cfg"

class TestKeyring(keyring.backend.KeyringBackend):
    """A faked keyring for test.
    """
    def supported(self):
        return 0

    def get_password(self, service, username):
        return PASSWORD_TEXT

    def set_password(self, service, username, password):
        return 0

class TestKeyring2(TestKeyring):
    """Another faked keyring for test.
    """
    def get_password(self, service, username):
        return PASSWORD_TEXT_2

class CoreTestCase(unittest.TestCase):
    def test_set_get_password(self):
        """Test the basic function of the keyring.
        """
        keyring.core.set_password("test", "user", "passtest")
        self.assertEqual(keyring.core.get_password("test", "user"), "passtest")

    def test_set_keyring_in_runtime(self):
        """Test the function of set keyring in runtime.
        """
        keyring.core.set_keyring(TestKeyring())

        keyring.core.set_password("test", "user", "password")
        self.assertEqual(keyring.core.get_password("test", "user"),
                                                                 PASSWORD_TEXT)

    def test_set_keyring_in_config(self):
        """Test setting the keyring by config file.
        """
        # create the config file
        config_file = open(KEYRINGRC,'w')
        config_file.writelines(["[backend]\n",
            # the path for the user created keyring
            "keyring-path= %s\n" % os.path.dirname(os.path.abspath(__file__)),
            # the name of the keyring class
            "default-keyring=test_core.TestKeyring2\n" ])
        config_file.close()

        # init the keyring lib, the lib will automaticlly load the
        # config file and load the user defined module
        keyring.core.init_backend()

        keyring.core.set_password("test", "user", "password")
        self.assertEqual(keyring.core.get_password("test", "user"),
            PASSWORD_TEXT_2)

        os.remove(KEYRINGRC)

    def test_load_config(self):
        tempdir = tempfile.mkdtemp()
        old_location = os.getcwd()
        os.chdir(tempdir)
        personal_cfg = os.path.join(os.path.expanduser("~"), "keyringrc.cfg")
        if os.path.exists(personal_cfg):
            os.rename(personal_cfg, personal_cfg+'.old')
            personal_renamed = True
        else:
            personal_renamed = False

        # loading with an empty environment
        keyring.core.load_config()

        # loading with a file that doesn't have a backend section
        cfg = os.path.join(tempdir, "keyringrc.cfg")
        f = open(cfg, 'w')
        f.write('[keyring]')
        f.close()
        keyring.core.load_config()

        # loading with a file that doesn't have a default-keyring value
        cfg = os.path.join(tempdir, "keyringrc.cfg")
        f = open(cfg, 'w')
        f.write('[backend]')
        f.close()
        keyring.core.load_config()

        os.chdir(old_location)
        shutil.rmtree(tempdir)
        if personal_renamed:
            os.rename(personal_cfg+'.old', personal_cfg)

class LocationTestCase(unittest.TestCase):
    legacy_location = os.path.expanduser('~/keyringrc.cfg')
    new_location = os.path.join(keyring.util.platform.data_root(),
        'keyringrc.cfg')

    @unittest.skipIf(os.path.exists(legacy_location),
        "Location test requires non-existence of ~/keyringrc.cfg")
    @unittest.skipIf(os.path.exists(new_location),
        "Location test requires non-existence of %(new_location)s"
        % vars())
    def test_moves_compat(self):
        """
        When starting the keyring module and ~/keyringrc.cfg exists, it
        should be moved and the user should be informed that it was
        moved.
        """
        # create the legacy config
        with open(self.legacy_location, 'w') as f:
            f.write('[test config]\n')

        # invoke load_config in a subprocess
        cmd = [sys.executable, '-c', 'import keyring.core; keyring.core.load_config()']
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        try:
            assert not os.path.exists(self.legacy_location)
            assert os.path.exists(self.new_location)
            with open(self.new_location) as f:
                assert 'test config' in f.read()
        finally:
            if os.path.exists(self.legacy_location):
                os.remove(self.legacy_location)
            if os.path.exists(self.new_location):
                os.remove(self.new_location)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CoreTestCase))
    suite.addTest(unittest.makeSuite(LocationTestCase))
    return suite

if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")
