#!/bin/bash

#!/bin/bash


PACKAGE_NAME="toa-dkms"
PACKAGE_VERSION="3.1.0"


POJ_DIR=..

SRC_DIR=$POJ_DIR/kmod
SCRIPTS_DIR=$POJ_DIR/scripts

DEB_DIR=$POJ_DIR/deb
DKMS_DIR=$DEB_DIR/usr/src/$PACKAGE_NAME-$PACKAGE_VERSION

mkdir -p $DEB_DIR
mkdir -p $DKMS_DIR


cp $SRC_DIR/toa.c             $DKMS_DIR
cp $SRC_DIR/toa.h             $DKMS_DIR
cp $SRC_DIR/Makefile          $DKMS_DIR
cp $SCRIPTS_DIR/toa_dkms.conf $DKMS_DIR/dkms.conf



# make deb package
# apt install ruby rubygems ruby-dev
# gem install fpm
fpm -s dir \
    -t deb \
    -p "$PACKAGE_NAME"_VERSION_ARCH.deb \
    --description 'toa' \
    -n $PACKAGE_NAME \
    -v $PACKAGE_VERSION \
    --after-install $SCRIPTS_DIR/toa_dkms_after_install.sh \
    --before-remove $SCRIPTS_DIR/toa_dkms_before_remove.sh \
    -C $DEB_DIR usr/


rm -rf $DEB_DIR



