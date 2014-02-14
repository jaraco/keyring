from __future__ import absolute_import

import os
import platform

def _settings_root_XP():
	return os.path.join(os.environ['USERPROFILE'], 'Local Settings')

def _settings_root_Vista():
	return os.environ.get('LOCALAPPDATA', os.environ.get('ProgramData', '.'))

def _data_root_Windows():
	release, version, csd, ptype = platform.win32_ver()
	root = _settings_root_XP() if release == 'XP' else _settings_root_Vista()
	return os.path.join(root, 'Python Keyring')

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
