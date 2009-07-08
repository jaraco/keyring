#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

"""

import sys,os

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

def find_library_file(compiler, libname, std_dirs, paths):
    result = compiler.find_library_file(std_dirs + paths, libname)
    if result is None:
        return None

    # Check whether the found file is in one of the standard directories
    dirname = os.path.dirname(result)
    for p in std_dirs:
        # Ensure path doesn't end with path separator
        p = p.rstrip(os.sep)
        if p == dirname:
            return [ ]

    # Otherwise, it must have been in one of the additional directories,
    # so we have to figure out which one.
    for p in paths:
        # Ensure path doesn't end with path separator
        p = p.rstrip(os.sep)
        if p == dirname:
            return [p]
    else:
        assert False, "Internal error: Path not found in std_dirs or paths"

class KeyringBuildExt(build_ext):
    
    def __init__(self,dist):
        build_ext.__init__(self,dist)

    def build_extensions(self):
        exts = []
        self.extensions = exts
        platform = self.get_platform()

        osx_keychain_module = Extension('osx_keychain',
                            library_dirs = ['/System/Library/Frameworks/'],
                            sources = ['keyring/backends/osx_keychain.c'],
                            extra_link_args = ['-framework','Security','-framework',
                                    'CoreFoundation','-framework','CoreServices'])

        if platform in ['darwin','mac']:
            exts.append(osx_keychain_module)

        lib_dirs = self.compiler.library_dirs + [
            '/lib64','/usr/lib64',
            '/lib','/usr/lib',
            ]
        inc_dirs = self.compiler.include_dirs + ['/usr/include']

        gnome_keychain_module = Extension('gnome_keyring',
							include_dirs = ['/usr/include/glib-2.0/',
                            '/usr/lib/glib-2.0/include','/usr/include/dbus-1.0/',
                            '/usr/lib/dbus-1.0/include/','/usr/include/gnome-keyring-1/'],
							libraries = ['glib-2.0','gnome-keyring'],
							sources = ['keyring/backends/gnome_keyring.c'],
				)
        
        exts.append(gnome_keychain_module)

        kde_kwallet_module = Extension('kde_kwallet',
							include_dirs = ['/usr/include/glib-2.0/',
                            '/usr/lib/glib-2.0/include','/usr/include/dbus-1.0/',
                            '/usr/lib/dbus-1.0/include/','/usr/include/qt4/','/usr/include/kde/',
                            '/usr/include/qt4/Qt/'],
							libraries = ['glib-2.0','QtCore','QtGui','dbus-1',
                            'kdeinit4_kwalletd'],
							library_dirs = ['/usr/lib/qt4/'],
							sources = ['keyring/backends/kde_kwallet.cpp'],
				)
        
        exts.append(kde_kwallet_module)

        build_ext.build_extensions(self)

    def get_platform(self):
        return sys.platform

def main():
    setup(name='keyring',
          version = "0.01",
          url = "http://bitbucket.org/kang/python-kering-lib",
          maintainer = "Kang Zhang",
          maintainer_email = "jobo.zh@gmail.com",
          platforms = ["Many"],

          #Buildinfo
          cmdclass = { 'build_ext':KeyringBuildExt },
          #Dummy item, to trigger the build_ext
          ext_modules = [None]
    
    )
# --install keyring lib
if __name__ == '__main__':
    main()
