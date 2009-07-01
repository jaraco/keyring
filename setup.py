#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

from distutils.core import setup, Extension

osx_keychain_moduel = Extension('osx_keychain',
							library_dirs = ['/System/Library/Frameworks/'],
							sources = ['keyring/backends/osx_keychain.c'],
							extra_link_args = ['-framework','Security','-framework',
									'CoreFoundation','-framework','CoreServices'])


setup(name="keyring",
	  version = '1.0',
	  ext_modules = [osx_keychain_moduel])

