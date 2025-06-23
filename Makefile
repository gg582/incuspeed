all:
	bash utils/make_incus_units.sh
	go build -o incuspeed
	cd tools
	go build -o tools/manage_ssh
	cd ..
