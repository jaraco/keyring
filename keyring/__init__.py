"""
__init__.py

Created by Kang Zhang on 2009-07-09
"""
import logging
logger = logging.getLogger('keyring')

from keyring.core import set_keyring, get_keyring, set_password, get_password
from keyring.getpassbackend import get_password as get_pass_get_password
