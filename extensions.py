"""
build_ext.py

Created by Kang Zhang on 2009-08-07
"""

import os
import sys
import commands

from distutils.core import Extension

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

def kde_exec(cmd, option):
    """Execute the kde-config command and get the output dirs
    """
    return commands.getoutput("%s %s" % (cmd, option)).split(':')

def kde_check(cmd, headfiles):
    includes = kde_exec(cmd, '--install include --expandvars')
    for filename in headfiles:
        # generate all possible paths for the headfile
        paths = [dir + filename for dir in includes]
        # check if file exists on any path
        exists = any([ os.path.exists(path) for path in paths])
        if not exists:
            return False
    return True

def kde_config(cmd, keywords):
    """Add the compile parameters for kdelibs
    """

    # KDE guys hate pkg-config, so we need due with it seperately. :-(
    # See following link for more details
    #       http://lists.kde.org/?t=109647896600005&r=1&w=2

    keywords.setdefault('libraries', []).append('kdeui')

    libs = kde_exec(cmd, '--path lib')
    includes = kde_exec(cmd, '--install include')

    keywords.setdefault('library_dirs', []).extend(libs)
    keywords.setdefault('include_dirs', []).extend(includes)
    return keywords

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

    gnome_keyring_libs = ['dbus-1', 'glib-2.0', 'gnome-keyring-1']
    if pkg_check(gnome_keyring_libs):
        # gnome-keyring installed
        gnome_keychain_module = Extension('gnome_keyring',
                        sources = ['keyring/backends/gnome_keyring.c'],
                        **pkg_config(gnome_keyring_libs)
            )
        exts.append(gnome_keychain_module)

    # check for KWallet heardfiles
    kde_kwallet_headfiles = ['kwallet.h']
    kde_cmd = None
    for cmd in ('kde-config','kde4-config'):
        if kde_check(cmd, kde_kwallet_headfiles):
            kde_cmd = cmd

    # check for Kwallet related libs
    kde_kwallet_libs = ['dbus-1', 'glib-2.0', 'QtGui']
    if pkg_check(kde_kwallet_libs) and kde_cmd is not None:
        # KDE Kwallet is installed.
        kde_kwallet_module = Extension('kde_kwallet',
                        sources = ['keyring/backends/kde_kwallet.cpp'],
                        **kde_config(kde_cmd, pkg_config(kde_kwallet_libs))
            )
        exts.append(kde_kwallet_module)

    if platform in ['win32'] and sys.getwindowsversion()[-2] == 2:
        # windows 2k+
        win32_crypto_module = Extension('win32_crypto',
                libraries = ['crypt32'],
                sources = ['keyring/backends/win32_crypto.c'],)
        exts.append(win32_crypto_module)

    return exts
