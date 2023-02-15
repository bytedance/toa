

MULTI_HOOK_DIR := /usr/src/multi-hook-dkms-1.0.0


KBUILD_MODPOST_WARN=1


obj-m	+= toa.o
CFLAGS_toa.o := -DDEBUG
#-DTOA_USE_MULTI_HOOK -I$(MULTI_HOOK_DIR)


ifeq ($(KERNDIR), )
    KDIR	:= /lib/modules/$(shell uname -r)/build
else
    KDIR	:= $(KERNDIR)
endif
PWD	:= $(shell pwd)

# ccflags-y += -DTOA_IPV6_ENABLE
# ccflags-y += -DTOA_NAT64_ENABLE

# ifeq ($(DEBUG), 1)
# ccflags-y += -g -O0
# endif
.PHONY: insmod rmmod 
default: build

build: toa.ko
toa.ko: toa.c toa.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	-rm -f *.o *.ko *.mod *.mod.c modules.order  Module.symvers

insmod: rmmod build
	sudo insmod toa.ko toa_map_table_bits=14 vip_enable=1 v6_to_v4_enable=0 v6_to_v4_prefix_str=64:ff9b:: dyndbg=+p

rmmod:
	-sudo rmmod toa

