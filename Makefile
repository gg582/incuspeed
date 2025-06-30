all:
	git clone https://github.com/gg582/linux_virt_unit
	bash utils/make_incus_units.sh
	go build -o incuspeed
	cd tools
	go build -o manage_ssh
	cd ..
