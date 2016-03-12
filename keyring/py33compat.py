"""
Compatibility support for Python 3.3. Remove when Python 3.3 support is
no longer required.
"""

from .py27compat import builtins


def max(*args, **kwargs):
    """
    Add support for 'default' kwarg.

    >>> max([], default='res')
    'res'

    >>> max(default='res')
    Traceback (most recent call last):
    ...
    TypeError: ...

    >>> max('a', 'b', default='other')
    'b'
    """
    missing = object()
    default = kwargs.pop('default', missing)
    try:
        return builtins.max(*args, **kwargs)
    except ValueError as exc:
        if 'empty sequence' in str(exc) and default is not missing:
            return default
        raise
