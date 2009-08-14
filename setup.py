#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

from distutils.core import setup
from build_ext import KeyringBuildExt

"""Setup the Keyring Lib for Python.
"""
setup(name = 'keyring',
      version = "0.1",
      description = "Store and access your passwords safely.",
      url = "http://keyring-python.org/",
      maintainer = "Kang Zhang",
      maintainer_email = "jobo.zh@gmail.com",
      license="PSF",
      long_description = open('README.txt').read(),
      platforms = ["Many"],
      packages = ['keyring'],
      #Buildinfo
      cmdclass = { 'build_ext':KeyringBuildExt },
      #Dummy item, to trigger the build_ext
      ext_modules = [None]
    )

