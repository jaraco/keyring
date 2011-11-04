import os
import sys

def _data_root_win32():
	return os.path.join(os.environ['LOCALAPPDATA'], 'Python Keyring')

def _data_root_linux2():
	"""
	Use freedesktop.org Base Dir Specfication to determine storage
	location.
	"""
	fallback = os.path.expanduser('~/.local/share')
	root = os.environ.get('XDG_DATA_HOME', None) or fallback
	return os.path.join(root, 'python_keyring')

# by default, use Unix convention
data_root = globals().get('_data_root_' + sys.platform, _data_root_linux2)
