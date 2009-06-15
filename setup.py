#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

from distutils.core import setup, Extension

osx_keychain_moduel = Extension('osx_keychain',
							library_dirs = ['/System/Library/Frameworks/'],
							sources = ['pykeyring/osx_keychain/osx_keychain.c'],
							extra_link_args = ['-framework','Security','-framework',
									'CoreFoundation','-framework','CoreServices'])


setup(name="pykeyring",
	  version = '1.0',
	  ext_modules = [osx_keychain_moduel])

