#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys


setup_params = dict(
    name = 'keyring',
    version = "1.0",
    description = "Store and access your passwords safely.",
    url = "http://home.python-keyring.org/",
    keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
    author = "Kang Zhang",
    author_email = "jobo.zh@gmail.com",
    maintainer = 'Jason R. Coombs',
    maintainer_email = 'jaraco@jaraco.com',
    license="PSF",
    long_description = open('README').read() + open('CHANGES.txt').read(),
    platforms = ["Many"],
    packages = ['keyring', 'keyring.tests', 'keyring.util',
                'keyring.backends'],
    extras_require={'test': []},
)


if sys.version_info >= (3,0):
    setup_params.update(
        use_2to3=True,
    )

elif sys.version_info < (2, 7) or (
    sys.version >= (3, 0) and sys.version < (3, 1)):
    # Provide unittest2 for Python which doesn't contain the new unittest module
    # (appears in Python 2.7 and Python 3.1)
    setup_params.update(
        tests_require=['unittest2'],
    )
    setup_params['extras_require']['test'].append('unittest2')


if __name__ == '__main__':
    try:
        from setuptools import setup
    except ImportError:
        from distutils.core import setup
    setup(**setup_params)
