#!/usr/bin/env python

# Project skeleton maintained at https://github.com/jaraco/skeleton

import io
import sys

import setuptools

with io.open('README.rst', encoding='utf-8') as readme:
    long_description = readme.read()

needs_wheel = {'release', 'bdist_wheel', 'dists'}.intersection(sys.argv)
wheel = ['wheel'] if needs_wheel else []

name = 'keyring'
description = 'Store and access your passwords safely.'

setup_params = dict(
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
    namespace_packages=name.split('.')[:-1],
    install_requires=[
    ],
    extras_require={
        ':sys_platform=="win32"': ['pywin32-ctypes'],
        ':sys_platform=="linux2" or sys_platform=="linux"': [
            "secretstorage",
        ],
    },
    setup_requires=[
        'setuptools_scm>=1.9,!=1.13.1,!=1.14.0',
    ] + wheel,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Python Software Foundation License",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
    ],
    entry_points={
        'console_scripts': [
            'keyring=keyring.cli:main',
        ],
    },
)
if __name__ == '__main__':
    setuptools.setup(**setup_params)
