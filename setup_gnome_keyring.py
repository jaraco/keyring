#!/usr/bin/env python
# encoding: utf-8
"""
setup_gnome_keyring.py

"""

from distutils.core import setup, Extension

gnome_keychain_moduel = Extension('gnome_keyring',
							include_dirs = ['/usr/include/glib-2.0/','/usr/lib/glib-2.0/include','/usr/include/dbus-1.0/','/usr/lib/dbus-1.0/include/','/usr/include/gnome-keyring-1/'],
							libraries = ['glib-2.0','gnome-keyring'],
							sources = ['keyring/backends/gnome_keyring.c'],
				)


setup(name="keyring",
	  version = '1.0',
	  ext_modules = [gnome_keychain_moduel])

