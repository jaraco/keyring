"""
escape/unescape routines available for backends which need
alphanumeric usernames, services, or other values
"""

import string, re

LEGAL_CHARS = string.letters + string.digits
ESCAPE_CHAR = "_"

def escape(value):
    """Escapes given value so the result consists of alphanumeric chars and underscore
    only, and alphanumeric chars are preserved"""
    def escape_char(c, legal = LEGAL_CHARS):
        # Single char escape. Either normal char, or _<hexcode>
        if c in legal:
            return c
        else:
            return "%s%X" % (ESCAPE_CHAR, ord(c))
    return "".join( escape_char(c) for c in value )

def unescape(value):
    """Reverts escape"""
    re_esc = re.compile("_([0-9A-F]{2})")
    return re_esc.sub(lambda i: chr(int(i.group(1),16)), value)
