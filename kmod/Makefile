


obj-m	+= toa.o

CFLAGS_toa.o := -DDEBUG

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
#default: insmod

build: toa.ko
toa.ko: toa.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	# $(MAKE) -C $(KDIR) M=$(PWD) modules clean
	-rm -f *.o *.ko *.mod *.mod.c modules.order  Module.symvers

# install:
# 	if [ -d "$(INSDIR)" ]; then \
# 		install -m 664 toa.ko $(INSDIR)/toa.ko; \
# 	fi

insmod: rmmod build
	sudo insmod toa.ko toa_map_table_bits=14 vip_enable=1 v6_to_v4_enable=0 v6_to_v4_prefix_str=64:ff9b:: dyndbg=+p

rmmod:
	-sudo rmmod toa