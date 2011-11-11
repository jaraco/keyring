# borrowed from jaraco.util.dictlib
class NonDataProperty(object):
	"""Much like the property builtin, but only implements __get__,
	making it a non-data property, and can be subsequently reset.

	See http://users.rcn.com/python/download/Descriptor.htm for more
	information.

	>>> class X(object):
	...   @NonDataProperty
	...   def foo(self):
	...     return 3
	>>> x = X()
	>>> x.foo
	3
	>>> x.foo = 4
	>>> x.foo
	4
	"""

	def __init__(self, fget):
		assert fget is not None, "fget cannot be none"
		assert callable(fget), "fget must be callable"
		self.fget = fget

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return self.fget(obj)
