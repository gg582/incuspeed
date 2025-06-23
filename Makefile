all:
	bash utils/make_incus_units.sh
	go build -o incuspeed
	cd tools
	go build manage_ssh.go
	cd ..
