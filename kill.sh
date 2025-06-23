#!/bin/bash


kill -9 $(pgrep incuspeed)
kill -9 $(pgrep server.sh)
incus stop $(incus list | awk '{print $2}' | sed '1,2d') --force
cp /etc/nginx/nginx.conf /usr/local/bin/incuspeed/backup.conf
