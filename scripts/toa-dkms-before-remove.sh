#!/bin/bash

echo "toa-dkms-before-remove.sh"
echo "arg0: $0"
echo "arg1: $1"
echo "arg2: $2"
echo "arg3: $3"

# remove dkms
PACKAGE_NAME="toa-dkms"
PACKAGE_VERSION="2.4.1"

case "$1" in
    remove|upgrade|deconfigure)

        echo "1"
        modprobe -r toa

        echo "2"
        rm -f /etc/modprobe.d/toa.conf

        echo "2"
        rm -f /usr/lib/modules-load.d/toa.conf

        echo "3"
        if [  "$(dkms status -m $PACKAGE_NAME -v $PACKAGE_VERSION)" ]; then
            dkms remove -m $PACKAGE_NAME -v $PACKAGE_VERSION --all
        fi

        echo "4"
    ;;
esac
