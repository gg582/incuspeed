#!/bin/bash
TAG="$1"
source /root/.bashrc
source /etc/environment
incus stop $TAG
incus delete $TAG
echo -n > /usr/local/bin/linuxVirtualization/container/latest_access
sudo rm -rf nohup*.out

kill -9 `pgrep init_server`
