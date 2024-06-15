# Miney
Super-Lightweight LXD container management front-end app for linux
Default distro is ubuntu:23:04.

## Getting Started
####  Installation on Server
  ssh management port is given port.
  xrdp management port is given port + 1.
* make
* ./initial_setup.sh --reconfigure-lxd
* systemctl start --now linuxVirtualization
### GUI Application
#### Usage
cd app
python3 main.py
You can connect into my computer's allocation service.
default login( id: root, password: PASSWORD)
be sure to change it.
#### Requirements 
* python3,requests,kivy

### Back-end Application
* Written in Go, binary is generated when you run Make Task
* Working as RESTful Server.
#### About Virtual Machines Management
* Virtual Machines are managed by LXD.
* All connections can be managed in a single domain
* Used Nginx Reverse-Proxy, it still needs more tasks to get stable software. So this is yet experimental.
  
