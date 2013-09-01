"""
Python 2.5 (and earlier) compatibility support. Remove this module when Python
2.5 compatibility is no longer required.
"""

try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = None

try:
    import abc

    def is_abstract(cls):
        return bool(cls.__abstractmethods__)
except ImportError:
    class ABCMeta(type):
        pass

    def abstractmethod(funcobj):
        return funcobj

    def abstractproperty(funcobj):
        return property(funcobj)

    # here's a little trick to treat this module as 'abc'
    abc = __import__('sys').modules[__name__]

    def is_abstract(cls):
        "A hacky workaround"
        return cls.__name__ in ('KeyringBackend', 'BaseKeyring')

try:
    import io
    BytesIO = io.BytesIO
except ImportError:
    import StringIO
    BytesIO = StringIO.StringIO
