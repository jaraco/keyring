"""
Compatibility support for Python 2.7. Remove when Python 2.7 support is
no longer required.
"""
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

if 'raw_input' in __builtins__:
    input = raw_input
else:
    input = input
