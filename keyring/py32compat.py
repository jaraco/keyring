try:
    from collections import abc
except ImportError:
    import collections as abc


__all__ = ['abc']
