#!/bin/bash
kill -9 $(pgrep incuspeed)
kill -9 $(pgrep server.sh)
source /root/.bashrc
cd /usr/local/bin/incuspeed
incus stop $(incus list | awk '{print $2}' | sed '1,2d') --force
incus delete $(incus list | awk '{print $2}' | sed '1,2d') --force
rm -rf container/incuspeed-*
rm -rf properties/incuspeed-*
if [ -f "container/latest_access" ]
then
    echo -n > container/latest_access
else
    if [ -f "container" ]
    then
        touch container/latest_access
    else
        mkdir container
        touch container/latest_access
    fi
fi
cp /usr/local/bin/incuspeed/nginx.conf /etc/nginx/nginx.conf
cp /usr/local/bin/incuspeed/nginx.conf /usr/local/bin/incuspeed/backup.conf
sudo rm -rf nohup*.out
systemctl restart --now nginx
cat drop_all.props | mongosh 
