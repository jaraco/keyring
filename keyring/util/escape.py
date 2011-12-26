"""
escape/unescape routines available for backends which need
alphanumeric usernames, services, or other values
"""

import string, re

LEGAL_CHARS = (
    getattr(string, 'letters', None) # Python 2
    or getattr(string, 'ascii_letters') # Python 3
) + string.digits

ESCAPE_FMT = "__x%X__"

def _escape_char(c):
    "Single char escape. Return the char, escaped if not already legal"
    return c if c in LEGAL_CHARS else ESCAPE_FMT % ord(c)

def escape(value):
    """
    Escapes given string so the result consists of alphanumeric chars and
    underscore only.
    """
    return "".join(_escape_char(c) for c in value)

def _unescape_code(regex_match):
    ordinal = int(regex_match.group('code'), 16)
    return unichr(ordinal)

def unescape(value):
    """
    Inverse of escape.
    """
    re_esc = re.compile(ESCAPE_FMT.replace('%X', '(?P<code>[0-9A-F]+)'))
    return re_esc.sub(_unescape_code, value)
