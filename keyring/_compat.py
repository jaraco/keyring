__all__ = ['properties']


try:
    from jaraco.classes import properties  # type: ignore  # pragma: no-cover
except ImportError:
    from . import _properties_compat as properties  # type: ignore  # pragma: no-cover
