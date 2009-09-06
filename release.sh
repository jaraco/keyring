#!/bin/sh
# build a source distrbution and a binary-one.
python setup.py register sdist upload
#python setup.py register bdist upload