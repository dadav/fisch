#!/bin/bash

mkdir -p /usr/local/share/fisch/
cp example.html /usr/local/share/fisch/
cp fisch.service /etc/systemd/system/
mkdir -p /usr/local/bin/
cp fisch.py /usr/local/bin/fisch
chmod a+x /usr/local/bin/fisch
