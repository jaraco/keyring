#!/usr/bin/env python
# encoding: utf-8
"""
setup.py

Setup the Keyring Lib for Python.
"""

import sys, os, subprocess
from distutils.core import setup, Extension
from distutils.version import StrictVersion

def runcmd(cmd, env):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    out, err = p.communicate()
    return out, err

if sys.platform == 'darwin' and os.path.exists('/usr/bin/xcodebuild'):
    # XCode 4.0 dropped support for ppc architecture, which is hardcoded in
    # distutils.sysconfig
    version = runcmd(['/usr/bin/xcodebuild', '-version'], {})[0].splitlines()[0]
    # Also parse only first digit, because 3.2.1 can't be parsed nicely
    if (version.startswith('Xcode') and
        StrictVersion(version.split()[1]) >= StrictVersion('4.0')):
        os.environ['ARCHFLAGS'] = ''

setup(name = 'keyring',
      version = "0.7",
      description = "Store and access your passwords safely.",
      url = "http://home.python-keyring.org/",
      keywords = "keyring Keychain GnomeKeyring Kwallet password storage",
      maintainer = "Kang Zhang",
      maintainer_email = "jobo.zh@gmail.com",
      license="PSF",
      long_description = open('README').read() + open('CHANGES.txt').read(),
      platforms = ["Many"],
      packages = ['keyring', 'keyring.tests', 'keyring.util',
                  'keyring.backends'],
    )

