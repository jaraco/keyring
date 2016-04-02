#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import setuptools_scm

extensions = [
    'sphinx.ext.autodoc',
    'rst.linker',
]

# General information about the project.
project = 'keyring'
copyright = '2015 Jason R. Coombs'

# The short X.Y version.
version = setuptools_scm.get_version(root='..', relative_to=__file__)
# The full version, including alpha/beta/rc tags.
release = version

master_doc = 'index'

link_files = {
	'CHANGES.rst': dict(
		using=dict(
			GH='https://github.com',
		),
		replace=[
			dict(
				pattern=r"(Issue )?#(?P<issue>\d+)",
				url='{GH}/jaraco/keyring/issues/{issue}',
			),
			dict(
				pattern=r"BB Pull Request ?#(?P<bb_pull_request>\d+)",
				url='{BB}/pypa/setuptools/pull-request/{bb_pull_request}',
			),
			dict(
				pattern=r"Distribute #(?P<distribute>\d+)",
				url='{BB}/tarek/distribute/issue/{distribute}',
			),
			dict(
				pattern=r"Buildout #(?P<buildout>\d+)",
				url='{GH}/buildout/buildout/issues/{buildout}',
			),
			dict(
				pattern=r"Old Setuptools #(?P<old_setuptools>\d+)",
				url='http://bugs.python.org/setuptools/issue{old_setuptools}',
			),
			dict(
				pattern=r"Jython #(?P<jython>\d+)",
				url='http://bugs.jython.org/issue{jython}',
			),
			dict(
				pattern=r"Python #(?P<python>\d+)",
				url='http://bugs.python.org/issue{python}',
			),
			dict(
				pattern=r"Interop #(?P<interop>\d+)",
				url='{GH}/pypa/interoperability-peps/issues/{interop}',
			),
			dict(
				pattern=r"Pip #(?P<pip>\d+)",
				url='{GH}/pypa/pip/issues/{pip}',
			),
			dict(
				pattern=r"Packaging #(?P<packaging>\d+)",
				url='{GH}/pypa/packaging/issues/{packaging}',
			),
			dict(
				pattern=r"[Pp]ackaging (?P<packaging_ver>\d+(\.\d+)+)",
				url='{GH}/pypa/packaging/blob/{packaging_ver}/CHANGELOG.rst',
			),
			dict(
				pattern=r"PEP[- ](?P<pep_number>\d+)",
				url='https://www.python.org/dev/peps/pep-{pep_number:0>4}/',
			),
			dict(
				pattern=r"^(?m)((?P<scm_version>v?\d+(\.\d+){1,2}))\n[-=]+\n",
				with_scm="{text}\n{rev[timestamp]:%d %b %Y}\n",
			),
		],
	),
}
