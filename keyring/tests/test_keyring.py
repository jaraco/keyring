"""
test_keyring.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""


import random,unittest,string

ALPHABET = string.ascii_letters + string.digits

def random_string(k):
    """Generate a random string with length <i>k</i>
    """
    r = ''
    for i in range(0,k):
        r += random.choice(ALPHABET)
    return r

class KeyringBasicFunction(unittest.TestCase):
    def setUp(self):
        pass

if __name__ == '__main__':
    unittest.main()
