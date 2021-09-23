#!/bin/bash

TOA_DIR=..

if [ -z $TOA_DIR ]; then
	echo "TOA_DIR not set, will exit"
	exit 1
fi


PACKAGE_NAME="toa-dkms"
PACKAGE_VERSION="2.4.1"

DEST_DIR=dkms
mkdir -p $TOA_DIR/$DEST_DIR/usr/src

TOA_DKMS_DIR=$TOA_DIR/$DEST_DIR/usr/src/$PACKAGE_NAME-$PACKAGE_VERSION
mkdir -p $TOA_DKMS_DIR

#cp -R $TOA_DIR/toa.h $TOA_DKMS_DIR
cp -R $TOA_DIR/kmod/toa.c $TOA_DKMS_DIR
cp -R $TOA_DIR/kmod/Makefile $TOA_DKMS_DIR
cp -R $TOA_DIR/scripts/toa-dkms.conf $TOA_DKMS_DIR/dkms.conf


# make deb package
# apt install ruby rubygems ruby-dev
# gem install fpm
fpm -s dir \
    -t deb \
    -p "$PACKAGE_NAME"_VERSION_ARCH.deb \
    --description 'TOA module for TTGW' \
    -n $PACKAGE_NAME \
    -v 2.4.1 \
    --after-install $TOA_DIR/scripts/toa-dkms-after-install.sh \
    --before-remove $TOA_DIR/scripts/toa-dkms-before-remove.sh \
    -C $TOA_DIR/$DEST_DIR usr/

# remove temp files
rm -rf $TOA_DIR/$DEST_DIR
