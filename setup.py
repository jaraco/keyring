#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys
import codecs

import setuptools


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
    'fs>=0.5',
    'mock',
    'pycrypto',
]
"dependencies for running tests"

if sys.version_info < (2, 7) or (
        sys.version_info >= (3, 0) and sys.version_info < (3, 1)):
    # Require unittest2 for Python which doesn't contain the new unittest
    # module (appears in Python 2.7 and Python 3.1)
    test_requirements.append('unittest2')

if sys.version_info >= (3, 0):
    # gdata doesn't currently install on Python 3. Omit it also.
    # http://code.google.com/p/gdata-python-client/issues/detail?id=229
    test_requirements.remove('gdata')

    # keyczar doesn't currently install on Python 3. Omit it also.
    # http://code.google.com/p/keyczar/issues/detail?id=125
    test_requirements.remove('python-keyczar')

# only request pytest_runner when command-line indicates invocation
pytest_cmds = set(['pytest', 'test', 'ptr'])
pytest_runner = (
    ['pytest-runner>=2.1']
    if pytest_cmds.intersection(sys.argv) else
    []
)

setup_params = dict(
    name='keyring',
    use_scm_version=True,
    description="Store and access your passwords safely.",
    url="http://bitbucket.org/kang/python-keyring-lib",
    keywords="keyring Keychain GnomeKeyring Kwallet password storage",
    author="Kang Zhang",
    author_email="jobo.zh@gmail.com",
    maintainer='Jason R. Coombs',
    maintainer_email='jaraco@jaraco.com',
    license="PSF and MIT",
    long_description=load('README.rst') + load('CHANGES.rst'),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Python Software Foundation License",
        "License :: OSI Approved :: MIT License",
    ],
    platforms=["Many"],
    packages=setuptools.find_packages(),
    extras_require={'test': test_requirements},
    tests_require=test_requirements,
    setup_requires=[
        'setuptools_scm',
    ] + pytest_runner,
    entry_points={
        'console_scripts': [
            'keyring=keyring.cli:main',
        ],
    },
)


if __name__ == '__main__':
    setuptools.setup(**setup_params)
