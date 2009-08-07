#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

from distutils.core import setup
from build_ext import KeyringBuildExt

def main():
    """Setup the Keyring Lib for Python.
    """
    setup(name='keyring',
          version = "0.01",
          url = "http://bitbucket.org/kang/python-kering-lib",
          maintainer = "Kang Zhang",
          maintainer_email = "jobo.zh@gmail.com",
          platforms = ["Many"],
          packages = ['keyring'],
          #Buildinfo
          cmdclass = { 'build_ext':KeyringBuildExt },
          #Dummy item, to trigger the build_ext
          ext_modules = [None]
    
    )

# install keyring lib
if __name__ == '__main__':
    main()
