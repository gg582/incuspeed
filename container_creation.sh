#!/bin/bash
NET_INTERFACE="$(ip route get 1 | awk '{print $5}')"
TAG="$1"
PORT="$2"
VERSION="24.04"
SERVER_IP="$(ip route get 1 | awk '{print $7}')"
echo -n "TAG:"
echo $TAG
if [ $(arch)="x86_64" ]
then
		ARCH="amd64"
elif [ $(arch)="amd64" ]
then
		ARCH=$(arch)
else
		echo "Sorry, This architecture is not supported;" 1>&2
		echo "Supported architecture for Minecraft: amd64" 1>&2
		echo "Your architecture is $(arch)" 1>&2
		return
fi
lxc launch ubuntu/$VERSION/$ARCH $TAG 


while true ; do 
	CONTAINER_IP=`lxc list |  grep $TAG | awk '{print $6}' | grep --invert-match "|" | tr -s " " `
	LENGTH_IP=`echo $CONTAINER_IP | awk '{print length}'`
	if [  $LENGTH_IP = 0 ]; then
		sleep 0.5
	else 
		break
 fi
done
tail -n 1 /etc/nginx/nginx.conf | wc -c | xargs -I {} truncate /etc/nginx/nginx.conf -s -{}
echo "
	server {
		listen 0.0.0.0:$((PORT+1));
		proxy_pass $CONTAINER_IP:30000;
	}
	server {
		listen 0.0.0.0:$PORT;
		proxy_pass $CONTAINER_IP:3389;
	}
	server {
		listen 0.0.0.0:$((PORT+2));
		proxy_pass $CONTAINER_IP:8080;
	}

}" >> /etc/nginx/nginx.conf

nginx -s reload
echo -n "CURRENT IP:"
echo $CONTAINER_IP
lxc file push -r /usr/local/bin/linuxVirtualization/linuxVirtualization.zip $TAG/
lxc exec $TAG -- /bin/apt-get install -y unzip
lxc exec $TAG -- /bin/unzip /linuxVirtualization.zip 
lxc exec $TAG -- /usr/bin/mv    linuxVirtualization /linuxVirtualization
echo $TAG > /usr/local/bin/linuxVirtualization/container/latest_access
lxc exec $TAG -- /bin/apt-get install -y openssh-server 
lxc exec $TAG -- /bin/apt-get install -y ubuntu-gnome-desktop
lxc exec $TAG -- /bin/apt-get install -y xrdp
lxc exec $TAG -- /bin/rm -rf /etc/ssh/sshd_config
lxc exec $TAG -- /bin/systemctl restart --now ssh
lxc exec $TAG -- /bin/systemctl restart --now xrdp
lxc exec $TAG -- /bin/bash /linuxVirtualization/conSSH.sh $TAG
lxc stop $TAG
echo "LXC DEVICE STATUS:"
lxc list
