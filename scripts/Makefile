

.PHONY: build install uninstall

build: 
	./make_toa_dkms_deb.sh

install: build
	dpkg -i toa-dkms_3.1.0_amd64.deb

uninstall:
	-dpkg -r toa-dkms 
	-rm toa-dkms_3.1.0_amd64.deb