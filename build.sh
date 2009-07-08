#!/usr/bin/env bash
rm -r build
python setup.py -v build
sudo python setup.py -v install
