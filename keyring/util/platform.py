import os
import sys

# While we support Python 2.4, use a convoluted technique to import
#  platform from the stdlib.
# With Python 2.5 or later, just do "from __future__ import absolute_import"
#  and "import platform"
exec('__import__("platform", globals=dict())')
platform = sys.modules['platform']

def _data_root_Windows():
	return os.path.join(os.environ['LOCALAPPDATA'], 'Python Keyring')

def _data_root_Linux():
	"""
	Use freedesktop.org Base Dir Specfication to determine storage
	location.
	"""
	fallback = os.path.expanduser('~/.local/share')
	root = os.environ.get('XDG_DATA_HOME', None) or fallback
	return os.path.join(root, 'python_keyring')

# by default, use Unix convention
data_root = globals().get('_data_root_' + platform.system(), _data_root_Linux)
