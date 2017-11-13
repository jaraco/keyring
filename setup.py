#!/usr/bin/env python

# Project skeleton maintained at https://github.com/jaraco/skeleton

import io

import setuptools

with io.open('README.rst', encoding='utf-8') as readme:
    long_description = readme.read()

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
    long_description=long_description,
    url="https://github.com/jaraco/" + name,
    packages=setuptools.find_packages(),
    include_package_data=True,
    namespace_packages=(
        name.split('.')[:-1] if nspkg_technique == 'managed'
        else []
    ),
    python_requires='>=2.7',
    install_requires=[
    ],
    extras_require={
        ':sys_platform=="win32"': [
            'pywin32-ctypes!=0.1.0,!=0.1.1',
        ],
        ':sys_platform=="linux2" or sys_platform=="linux"': [
            "secretstorage",
        ],
        'testing': [
            'pytest>=2.8',
            'pytest-sugar',
            'collective.checkdocs',
        ],
        'docs': [
            'sphinx',
            'jaraco.packaging>=3.2',
            'rst.linker>=1.9',
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
    ],
    entry_points={
        'console_scripts': [
            'keyring=keyring.cli:main',
        ],
        'devpi_client': [
            'keyring = keyring.devpi_client',
        ],
    },
)
if __name__ == '__main__':
    setuptools.setup(**params)
