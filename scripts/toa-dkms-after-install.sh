#!/bin/bash

echo "toa-dkms-after-install.sh"
echo "arg0: $0"
echo "arg1: $1"
echo "arg2: $2"
echo "arg3: $3"


PACKAGE_NAME="toa-dkms"
PACKAGE_VERSION="2.4.1"

DKMS_POSTINST=/usr/lib/dkms/common.postinst


function check_kernel_version()
{
    string=$(uname -r)
    array=(${string//./ })
    version=${array[0]}
    major=${array[1]}
    minor=${array[2]}

    if  [[ $version -lt 4 ]]
    then
        echo "kernel version is $string, older than 4.14"
        exit 1
    elif [[ $version -eq 4 && $major -lt 14 ]]
    then
        echo "kernel version is $string, older then 4.14"
    fi

    return 0
}

case "$1" in
	configure)

        echo "0"
        check_kernel_version

        # dkms
        echo "1"
        if [ ! -f $DKMS_POSTINST ]; then
            echo "ERROR: DKMS version is too old and $PACKAGE_NAME was not"
            echo "built with legacy DKMS support."
            echo "You must either rebuild $PACKAGE_NAME with legacy postinst"
            echo "support or upgrade DKMS to a more current version."
            exit 1
        fi

        echo "2"
        $DKMS_POSTINST $PACKAGE_NAME $PACKAGE_VERSION "" "" $2

        echo "3"
        echo "toa" > /usr/lib/modules-load.d/toa.conf

        echo "4" 
        echo "options toa toa_map_table_bits=14 vip_enable=1 v6_to_v4_enable=0 v6_to_v4_prefix_str=64:ff9b:: dyndbg=-p" > /etc/modprobe.d/toa.conf

        echo "5" 
        modprobe toa

        echo "6"

	;;
esac
