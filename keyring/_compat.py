__all__ = ['properties']


try:
    from jaraco.compat import properties  # pragma: no-cover
except ImportError:
    from . import _properties_compat as properties  # pragma: no-cover
