from __future__ import absolute_import

import logging
logger = logging.getLogger('keyring')

from .core import (set_keyring, get_keyring, set_password, get_password,
                  delete_password)
from .getpassbackend import get_password as get_pass_get_password

try:
	import pkg_resources
	__version__ = pkg_resources.require('keyring')[0].version
except Exception:
	__version__ = 'unknown'
