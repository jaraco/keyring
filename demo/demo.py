#!/usr/bin/env python
# encoding: utf-8
"""
demo.py

Created by Kang Zhang on 2009-06-13.
"""

import sys
import os
import osx_keychain


def main():
	"""
	This script demos the pykeyring on osx. To see the changes that
	pykeyring has made on your machine, open your Keychain Access and
	search for demo-service in your login keychain.
	"""
	if osx_keychain.password_set("demo-service","tarek","passexample") == 0:
		print "password stored sucessful"
		
	print osx_keychain.password_get("demo-service","tarek")
	pass


if __name__ == '__main__':
	main()

