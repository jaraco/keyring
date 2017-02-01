#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

if 'check_output' not in dir(subprocess):
	import subprocess32 as subprocess

extensions = [
    'sphinx.ext.autodoc',
    'rst.linker',
]

# General information about the project.

root = os.path.join(os.path.dirname(__file__), '..')
setup_script = os.path.join(root, 'setup.py')
fields = ['--name', '--version', '--url', '--author']
dist_info_cmd = [sys.executable, setup_script] + fields
output_bytes = subprocess.check_output(dist_info_cmd, cwd=root)
project, version, url, author = output_bytes.decode('utf-8').strip().split('\n')

copyright = '2016 ' + author

# The full version, including alpha/beta/rc tags.
release = version

master_doc = 'index'

link_files = {
	'../CHANGES.rst': dict(
		using=dict(
			GH='https://github.com',
			project=project,
			url=url,
		),
		replace=[
			dict(
				pattern=r"(Issue )?#(?P<issue>\d+)",
				url='{url}/issues/{issue}',
			),
			dict(
				pattern=r"^(?m)((?P<scm_version>v?\d+(\.\d+){1,2}))\n[-=]+\n",
				with_scm="{text}\n{rev[timestamp]:%d %b %Y}\n",
			),
			dict(
				pattern=r"PEP[- ](?P<pep_number>\d+)",
				url='https://www.python.org/dev/peps/pep-{pep_number:0>4}/',
			),
		],
	),
}
