#!/usr/bin/env bash

if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

pip3 install -r requirements.txt
pip3 install -e .
cp srv6ping /usr/local/bin/
chmod +x /usr/local/bin/srv6ping