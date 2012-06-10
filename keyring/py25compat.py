"""
Python 2.5 compatibility support. Remove this module when Python 2.5
compatibility is no longer required.
"""

try:
	import json
except ImportError:
	try:
		import simplejson as json
	except ImportError:
		pass
