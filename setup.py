#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys
from distutils.core import setup, Extension

from extensions import get_extensions

setup(name = 'keyring',
      version = "0.5.1",
      description = "Store and access your passwords safely.",
      url = "http://home.python-keyring.org/",
      keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
      maintainer = "Kang Zhang",
      maintainer_email = "jobo.zh@gmail.com",
      license="PSF",
      long_description = open('README.txt').read() + open('CHANGES.txt').read(),
      platforms = ["Many"],
      packages = ['keyring', 'keyring.tests', 'keyring.util',
                  'keyring.backends'],
      ext_modules = get_extensions()
    )

