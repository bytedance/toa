

.PHONY: build install uninstall

build: 
	./make-toa-dkms-deb.sh

install: build
	dpkg -i toa-dkms_2.4.1_amd64.deb
#	modprobe toa

uninstall:
# 	-modprobe -r toa
	-dpkg -r toa-dkms 
	-rm toa-dkms_2.4.1_amd64.deb