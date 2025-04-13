#!/bin/bash
VERSION="24.04"
OPTION=$1
if [ -z $OPTION ] 
then
	OPTION="NONE"
fi
echo "Setup script of Virtualization Management Server -- "
sleep  0.5
if [ $(whoami) = "root" ]
then
		echo "Already admin! Entering setup.."
    echo "Be sure to locate your linuxVirtualization ZIP"
else
		echo "Please enter your password to switch to root"
		sudo -s
fi
sleep 1
make
apt-get update -y
apt remove ufw -y
apt-get install -y gnupg curl firewalld
vi /etc/firewalld/firewalld.conf
firewall-cmd --reload
firewall-cmd --zone=public --add-port=32000/tcp
curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | \
   gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg \
   --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
apt-get update -y
apt-get  -y install mongodb-org nginx nginx-extras
if [ ! -f "/var/lib/snapd/snap/bin" ]
then
    echo "PATH=$PATH":/snap/bin"" >> /etc/environment
    source /root/.bashrc
    systemctl enable snapd
    systemctl start snapd
fi
#ausearch -c 'snap-confine- - | audit2allow -M my-snapconfine'
#semodule -X 300 -i my-snapconfine.pp
#cat > mongodb_cgroup_memory.te <<EOF
#module mongodb_cgroup_memory 1.0;
#require {
#      type cgroup_t;
#      type mongod_t;
#      class dir search;
#      class file { getattr open read };
#}
##============= mongod_t ==============
#allow mongod_t cgroup_t:dir search;
#allow mongod_t cgroup_t:file { getattr open read };
#EOF
#checkmodule -M -m -o mongodb_cgroup_memory.mod mongodb_cgroup_memory.te
#semodule_package -o mongodb_cgroup_memory.pp -m mongodb_cgroup_memory.mod
#sudo semodule -i mongodb_cgroup_memory.pp
#sudo semanage port -a -t mongod_port_t -p tcp 19999
systemctl restart mongod
if [ $OPTION = "--reconfigure-incus" ]
then
    systemctl stop incus.socket
    systemctl stop incus.service
    apt-get  -y purge --autoremove incus
    ip link delete incusbr0
    rm -rf /var/lib/incus
	apt-get -y install incus
    systemctl enable --now incus.service
    systemctl enable --now incus.socket
fi
NET_INTERFACE="$(ip route get 1 | awk '{print $5}')"
incus profile device set default $NET_INTERFACE nictype bridged
BRIDGE_NAME=incusbr0
INTERFACE_NAME=$(ip route get 1 | awk '{print $5}')
IP_ADDRESS=$(ip route get 1 | awk '{print $7}')

sleep 2
cat mongo.props | mongosh --port 27017

#systemctl stop --now dnsmasq
#systemctl disable dnsmasq
mkdir container
touch container/latest_access

firewall-cmd --permanent --zone=public --add-port 8843/tcp
firewall-cmd --permanent --zone=public --add-port 53/tcp
firewall-cmd --permanent --zone=public --add-port 67/tcp
firewall-cmd --permanent --zone=public --add-port 8843/udp
firewall-cmd --permanent --zone=public --add-port 19132/tcp
firewall-cmd --permanent --zone=public --add-port 19132/udp
firewall-cmd --permanent --zone=public --add-port 19133/tcp
firewall-cmd --permanent --zone=public --add-port 19133/udp
firewall-cmd --permanent --zone=public --add-port 25565/tcp
firewall-cmd --permanent --zone=public --add-port 25565/udp
firewall-cmd --permanent --zone=public --add-port 25566/tcp
firewall-cmd --permanent --zone=public --add-port 25566/udp
firewall-cmd --permanent --zone=public --add-port 32000/tcp
#for i in {30000..30001..60000}
#do 
#		semanage port -a -t http_port_t -p tcp $i
#done
firewall-cmd --permanent --zone=public --add-port 25565-60000/udp
firewall-cmd --permanent --zone=public --add-port 25565-60000/tcp
firewall-cmd --permanent --zone=public --add-port 8843/udp
firewall-cmd --permanent --zone=public --add-port 8843/tcp
firewall-cmd --zone=trusted --change-interface=incusbr0 --permanent
apt install iptables-persistent -y
iptables -I FORWARD 1 -i incusbr0 -j ACCEPT
iptables -I FORWARD 1 -o incusbr0 -j ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -A INPUT -p tcp --dport 27020:60000 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 27020:60000 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 27020:60000 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 27020:60000 -j ACCEPT
netfilter-persistent save

#ausearch -c 'nginx' --raw | audit2allow -M my-nginx
#semodule -X 300 -i my-nginx.pp
./install_svc.sh
systemctl restart NetworkManager
incus admin init
./utils/make_base_images.sh
mkdir certs
mkdir app/certs
./utils/keygen.sh
