import sys

__all__ = ['metadata']


if sys.version_info >= (3, 12):
    from importlib import metadata
else:
    import importlib_metadata as metadata
