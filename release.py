#!/usr/bin/env python

"""
release.py - releases keyring to the cheeseshop
"""

import subprocess

# we only upload a source distribution now as there are no C extensions
subprocess.Popen([sys.executable, 'setup.py', 'sdist', 'upload'])
