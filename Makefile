all:
	bash utils/make_incus_units.sh
	go build -o server
