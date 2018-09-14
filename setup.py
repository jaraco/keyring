#!/usr/bin/env python

# Project skeleton maintained at https://github.com/jaraco/skeleton

import setuptools

name = 'keyring'
description = 'Store and access your passwords safely.'
nspkg_technique = 'native'
"""
Does this package use "native" namespace packages or
pkg_resources "managed" namespace packages?
"""

params = dict(
    name=name,
    use_scm_version=True,
    author="Kang Zhang",
    author_email="jobo.zh@gmail.com",
    maintainer='Jason R. Coombs',
    maintainer_email='jaraco@jaraco.com',
    description=description or name,
    url="https://github.com/jaraco/" + name,
    packages=setuptools.find_packages(),
    include_package_data=True,
    namespace_packages=(
        name.split('.')[:-1] if nspkg_technique == 'managed'
        else []
    ),
    python_requires='>=2.7',
    install_requires=[
        'entrypoints',
    ],
    extras_require={
        'testing': [
            # upstream
            'pytest>=3.5,!=3.7.3',
            'pytest-sugar>=0.9.1',
            'collective.checkdocs',
            'pytest-flake8',

            # local
        ],
        'docs': [
            # upstream
            'sphinx',
            'jaraco.packaging>=3.2',
            'rst.linker>=1.9',

            # local
        ],
        ':sys_platform=="win32"': [
            'pywin32-ctypes!=0.1.0,!=0.1.1',
        ],
        ':sys_platform=="linux" and python_version>="3.5"': [
            "secretstorage",
        ],
        ':(sys_platform=="linux2" or sys_platform=="linux")'
        ' and python_version<"3.5"': [
            "secretstorage<3",
        ],
    },
    setup_requires=[
        'setuptools_scm>=1.15.0',
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Python Software Foundation License",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    entry_points={
        'console_scripts': [
            'keyring=keyring.cli:main',
        ],
        'devpi_client': [
            'keyring = keyring.devpi_client',
        ],
        'keyring.backends': [
            'Windows = keyring.backends.Windows',
            'macOS = keyring.backends.OS_X',
            'SecretService = keyring.backends.SecretService',
            'KWallet = keyring.backends.kwallet',
        ],
    },
)
if __name__ == '__main__':
    setuptools.setup(**params)
