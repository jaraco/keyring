#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys
import codecs

try:
    import setuptools
    setup_mod = setuptools
    "where to find setup()"
except ImportError:
    import distutils.core
    setup_mod = distutils.core

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


test_requirements = [
    'pytest',
    'gdata',
    'python-keyczar',
    'fs',
    'mock',
    'pycrypto',
]
"dependencies for running tests"

if sys.version_info < (2, 7) or (
        sys.version_info >= (3, 0) and sys.version_info < (3, 1)):
    # Require unittest2 for Python which doesn't contain the new unittest
    # module (appears in Python 2.7 and Python 3.2.1)
    test_requirements.append('unittest2')

if sys.version_info >= (3, 0):
    # the fs lib doesn't currently install on Python 3. Omit it for now.
    # See http://code.google.com/p/pyfilesystem/issues/detail?id=135
    test_requirements.remove('fs')

    # gdata doesn't currently install on Python 3. Omit it also.
    # http://code.google.com/p/gdata-python-client/issues/detail?id=229
    test_requirements.remove('gdata')

    # keyczar doesn't currently install on Python 3. Omit it also.
    # http://code.google.com/p/keyczar/issues/detail?id=125
    test_requirements.remove('python-keyczar')

# only request pytest_runner when command-line indicates invocation
pytest_runner = ['pytest-runner'] if 'ptr' in sys.argv else []

setup_params = dict(
    name = 'keyring',
    version = "3.2.1",
    description = "Store and access your passwords safely.",
    url = "http://bitbucket.org/kang/python-keyring-lib",
    keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
    author = "Kang Zhang",
    author_email = "jobo.zh@gmail.com",
    maintainer = 'Jason R. Coombs',
    maintainer_email = 'jaraco@jaraco.com',
    license = "PSF",
    long_description = load('README.rst') + load('CHANGES.rst'),
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
    platforms = ["Many"],
    packages = ['keyring', 'keyring.tests', 'keyring.util',
                'keyring.backends', 'keyring.tests.backends'],
    extras_require = {'test': test_requirements},
    tests_require = test_requirements,
    setup_requires = [
    ] + pytest_runner,
    entry_points = {
        'console_scripts': [
            'keyring=keyring.cli:main',
        ],
    },
)


if __name__ == '__main__':
    setup_mod.setup(**setup_params)
