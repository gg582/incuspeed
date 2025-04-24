all:
	bash utils/make_incus_units.sh
	go build -o linuxVirtualizationServer 
	cd tools
	go build -o tools/manage_ssh
	cd ..
