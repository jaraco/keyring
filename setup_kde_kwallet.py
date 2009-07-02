#!/usr/bin/env python
# encoding: utf-8
"""
setup_gnome_keyring.py

"""

from distutils.core import setup, Extension

gnome_keychain_moduel = Extension('kde_kwallet',
							include_dirs = ['/usr/include/glib-2.0/','/usr/lib/glib-2.0/include','/usr/include/dbus-1.0/','/usr/lib/dbus-1.0/include/','/usr/include/qt4/'],
							libraries = ['glib-2.0','QtCore','QtGui','dbus-1','kdeinit4_kwalletd'],
							library_dirs = ['/usr/lib/qt4/'],
							sources = ['keyring/backends/kde_kwallet.cpp'],
				)


setup(name="keyring",
	  version = '1.0',
	  ext_modules = [gnome_keychain_moduel])

