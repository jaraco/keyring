# -*- coding: utf-8 -*-


from ..test_backend import BackendBasicTests
from ..py30compat import unittest
from keyring.backends import S3


@unittest.skipUnless(S3.supported(),
                     "You need to configure the AWS credentials")
class S3PlaintextKeychainTestCase(BackendBasicTests, unittest.TestCase):
    def init_keyring(self):
        return S3.PlaintextKeyring()
