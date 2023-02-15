

.PHONY: build install uninstall

build: 
	./make_toa_dkms_deb.sh

install: build
	dpkg -i toa-dkms_3.2.0-opensource_amd64.deb

uninstall:
	-dpkg -r toa-dkms 
	-rm toa-dkms_3.2.0-opensource_amd64.deb
