#!/bin/bash
cp -frp crysadm crysadm.old
cd tmp
unzip crysadm.zip
rm crysadm/config.py
cp -frp crysadm/* ../crysadm/
../run.sh
rm -rf *
