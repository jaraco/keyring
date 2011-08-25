"""
build_ext.py

Created by Kang Zhang on 2009-08-07
"""

import sys

from distutils.core import Extension


def get_extensions():
    """Collect the extensions that can be installed.
    """
    exts = []
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

    return exts
