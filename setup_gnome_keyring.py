#!/usr/bin/env python
# encoding: utf-8
"""
setup_gnome_keyring.py

"""

from distutils.core import setup, Extension

gnome_keychain_moduel = Extension('gnome_keyring',
							include_dirs = ['/usr/include/glib-2.0/','/usr/lib/glib-2.0/include','/usr/include/dbus-1.0/','/usr/lib/dbus-1.0/include/','/usr/include/gnome-keyring-1/'],
							libraries = ['glib-2.0','gnome-keyring'],
							sources = ['pykeyring/gnome_keyring/gnome_keyring.c'],
							#extra_link_args = ['-framework','Security','-framework',
							#		'CoreFoundation','-framework','CoreServices']
				)


setup(name="pykeyring",
	  version = '1.0',
	  ext_modules = [gnome_keychain_moduel])

