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

    if platform in ['win32'] and sys.getwindowsversion()[-2] == 2:
        # windows 2k+
        win32_crypto_module = Extension('win32_crypto',
                libraries = ['crypt32'],
                sources = ['keyring/backends/win32_crypto.c'],)
        exts.append(win32_crypto_module)

    return exts
