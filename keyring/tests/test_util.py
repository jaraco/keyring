# -*- coding: utf-8 -*-

"""
Test for simple escape/unescape routine
"""


import unittest
import os
import sys
import tempfile
import shutil

from keyring.util import escape

class EscapeTestCase(unittest.TestCase):

    def check_escape_unescape(self, initial):
        escaped = escape.escape(initial)
        self.assertTrue(all( c in (escape.LEGAL_CHARS + escape.ESCAPE_CHAR)
                             for c in escaped))
        unescaped = escape.unescape(escaped)
        self.assertEqual(initial, unescaped)

    def test_escape_unescape(self):
        self.check_escape_unescape("aaaa")
        self.check_escape_unescape("aaaa bbbb cccc")
        self.check_escape_unescape(u"Zażółć gęślą jaźń".encode("utf-8"))
        self.check_escape_unescape("(((P{{{{'''---; ;; '\"|%^")

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(EscapeTestCase))
    return suite

if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")
