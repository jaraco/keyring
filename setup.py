#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys
import codecs

def load(filename):
    """
    Read a text file and decode it.
    """
    f = codecs.open(filename, encoding='utf-8')
    try:
        result = f.read()
    finally:
        f.close()
    if not encodes_as_ascii(result):
        # see https://bitbucket.org/kang/python-keyring-lib/issue/55
        raise ValueError("distutils requires ASCII")
    return result

def encodes_as_ascii(string):
    try:
        string.encode('ascii')
    except UnicodeEncodeError:
        return False
    return True

setup_params = dict(
    name = 'keyring',
    version = "0.7.1",
    description = "Store and access your passwords safely.",
    url = "http://bitbucket.org/kang/python-keyring-lib",
    keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
    author = "Kang Zhang",
    author_email = "jobo.zh@gmail.com",
    maintainer = 'Jason R. Coombs',
    maintainer_email = 'jaraco@jaraco.com',
    license="PSF",
    long_description = load('README') + load('CHANGES.txt'),
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2.4",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
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
