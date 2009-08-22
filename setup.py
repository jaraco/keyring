#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys
from distutils.core import setup, Extension

from extensions import get_extensions

if sys.version_info[:2] < (2, 6):
    sys.exit("Python 2.6 or higher is required, %d.%d.%d found." %
             sys.version_info[:3])

setup(name = 'keyring',
      version = "0.1",
      description = "Store and access your passwords safely.",
      url = "http://keyring-python.org/",
      keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
      maintainer = "Kang Zhang",
      maintainer_email = "jobo.zh@gmail.com",
      license="PSF",
      long_description = open('README.txt').read(),
      platforms = ["Many"],
      packages = ['keyring'],
      ext_modules = get_extensions()
    )

