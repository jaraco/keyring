#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

import sys
import os
import commands
import re

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

def pkg_check(packages):
    """Return false if not all packages has been installed properly.
    """
    status, output = commands.getstatusoutput("pkg-config --exists %s" % 
                                                    ' '.join(packages))
    return len(output) == 0 and status == 0 

def pkg_config(packages):
    """Return the config parameters for all packages
    """
    keywords = {}
    flag_map = {'-I':'include_dirs', '-L':'library_dirs', '-l':'libraries'}

    for token in commands.getoutput("pkg-config --libs --cflags %s" % 
                                                ' '.join(packages)).split():
        try:
            key = flag_map[token[:2]]
            keywords.setdefault(key, []).append(token[2:])
        except KeyError:
            keywords.setdefault('extra_link_args', []).append(token)

    return keywords

def kde_config(keywords):
    """Add the compile parameter for kdelibs
    """

    # KDE guys hate pkg-config, so we need due with it seperately. :-(
    # See following link for more details
    #       http://lists.kde.org/?t=109647896600005&r=1&w=2

    keywords.setdefault('libraries',[]).append('kdeui')
    libs = commands.getoutput("kde4-config --path lib").split(':')
    if len(libs) == 0:
        libs = commands.getoutput("kde-config --path lib").split(':')
    keywords.setdefault('library_dirs',[]).extend(libs)
    return keywords

class KeyringBuildExt(build_ext):
    """Helper class to detect the enviroment and install the keyrings.
    """
    
    def __init__(self, dist):
        build_ext.__init__(self, dist)

    def build_extensions(self):
        """Collect the extensions that can be installed.
        """
        exts = []
        self.extensions = exts
        platform = sys.platform
        
        if platform in ['darwin', 'mac']:
            # Mac OS X, keychain enabled
            osx_keychain_module = Extension('osx_keychain',
                            library_dirs = ['/System/Library/Frameworks/'],
                            sources = ['keyring/backends/osx_keychain.c'],
                            extra_link_args = ['-framework', 'Security',
                                '-framework', 'CoreFoundation', '-framework',
                                'CoreServices'])
            exts.append(osx_keychain_module)

        gnome_keyring_libs = ['dbus-1', 'glib-2.0', 'gnome-keyring-1']
        if pkg_check(gnome_keyring_libs):
            # gnome-keyring installed
            gnome_keychain_module = Extension('gnome_keyring',
                            sources = ['keyring/backends/gnome_keyring.c'],
                            **pkg_config(gnome_keyring_libs)
                )
            exts.append(gnome_keychain_module)

        kde_kwallet_libs = ['dbus-1', 'glib-2.0', 'QtGui']
        if pkg_check(kde_kwallet_libs):
            # KDE Kwallet is installed.
            kde_kwallet_module = Extension('kde_kwallet',
                            sources = ['keyring/backends/kde_kwallet.cpp'],
                            **kde_config(pkg_config(kde_kwallet_libs))
                )
            exts.append(kde_kwallet_module)

        if platform in ['win32'] and sys.getwindowsversion()[-2] == 2:
            # windows 2k+
            win32_crypto_module = Extension('win32_crypto',
                    libraries = ['crypt32'],
                    sources = ['keyring/backends/win32_crypto.c'],)
            exts.append(win32_crypto_module)

        build_ext.build_extensions(self)

def main():
    """Setup the Keyring Lib for Python.
    """
    setup(name='keyring',
          version = "0.01",
          url = "http://bitbucket.org/kang/python-kering-lib",
          maintainer = "Kang Zhang",
          maintainer_email = "jobo.zh@gmail.com",
          platforms = ["Many"],
          packages = ['keyring'],
          #Buildinfo
          cmdclass = { 'build_ext':KeyringBuildExt },
          #Dummy item, to trigger the build_ext
          ext_modules = [None]
    
    )
# --install keyring lib
if __name__ == '__main__':
    main()
