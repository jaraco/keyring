"""
test_keyring.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""


import random, unittest, string, os, commands

ALPHABET = string.ascii_letters + string.digits

def random_string(k):
    """Generate a random string with length <i>k</i>
    """
    result = ''
    for i in range(0, k):
        result += random.choice(ALPHABET)
    return result 

def backup(file):
    """Backup the file as file.bak
    """
    commands.getoutput( "mv %s{,.bak}" % file )

def restore(file):
    """Restore the file from file.bak
    """
    commands.getoutput( "mv %s{.bak,}" % file )

class KeyringBasicFunction(unittest.TestCase):
    """Test for the keyring's basic funtions. password_set and password_get
    """
    def setUp(self):
        """Initialize the keyring lib.
        """
        from keyring import backend
        print backend.get_all_keyring()
        self.keyrings = [ k for k in backend.get_all_keyring() \
                                            if k.supported() >= 0 ]

    def testpassword_set_get(self):
        """Test the password_set and password_get funtions of keyring.
        """
        for keyring in self.keyrings:
            password = random_string(20)
            username = random_string(20)
            service = random_string(20)
            
            self.assertEqual(keyring.set_password(service, username, password), 
                                                                              0)

            self.assertEqual(keyring.get_password(service, username), password)

if __name__ == '__main__':
    unittest.main()
