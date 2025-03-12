#!/bin/bash
source /root/.bashrc
incus stop $(incus list | awk '{print $2}' | grep --invert-match NAME)
incus delete $(incus list | awk '{print $2}' | grep --invert-match NAME)
rm -rf container/linuxVirtualization-*
rm -rf properties/linuxVirtualization-*
cat drop_all.props | mongosh --port 27017
echo -n > container/latest_access
cp /usr/local/bin/linuxVirtualization/nginx.conf /etc/nginx/nginx.conf
sudo rm -rf nohup*.out

kill -9 `pgrep init_server`
