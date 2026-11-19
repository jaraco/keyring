import sys

__all__ = ['lazy_importer']


if sys.version_info < (3, 11) or sys.version_info >= (3, 15):
    from contextlib import nullcontext as lazy_importer
else:
    from lazy_importer import lazy_importer
