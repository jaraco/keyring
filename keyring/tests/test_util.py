# -*- coding: utf-8 -*-

"""
Test for simple escape/unescape routine
"""


import unittest

from keyring.util import escape

class EscapeTestCase(unittest.TestCase):

    def check_escape_unescape(self, initial):
        escaped = escape.escape(initial)
        self.assertTrue(all(c in (escape.LEGAL_CHARS + '_') for c in escaped))
        unescaped = escape.unescape(escaped)
        self.assertEqual(initial, unescaped)

    def test_escape_unescape(self):
        self.check_escape_unescape("aaaa")
        self.check_escape_unescape("aaaa bbbb cccc")
        self.check_escape_unescape(u"Zażółć gęślą jaźń")
        self.check_escape_unescape("(((P{{{{'''---; ;; '\"|%^")

    def test_low_byte(self):
        """
        The current encoding allows low bytes (less than hex 16) to encode
        as two bytes. For example '\n' (hex A) will encode as '_A', which
        isn't matched by the inverse operation.
        """
        self.check_escape_unescape('\n')

    def test_ambiguous_string(self):
        """
        The current encoding encodes each non-alphanumeric byte to _XX where
        XX is the hex code for that byte. However, it doesn't encode dual-
        digits, so '\x00' encodes to '_0'. Thus, if one tries to escape the
        string '\x000' (the null byte followed by the number 0), it will be
        encoded to '_00', which decodes to '\x00'.
        """
        self.check_escape_unescape('\x000')

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(EscapeTestCase))
    return suite

if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")
