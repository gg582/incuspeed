#!/bin/bash
if [ "$(whoami)" == "root" ]
then
    rm -r /usr/local/bin/incuspeed
    rm -r /usr/local/bin/conSSH.sh
    rm -r /usr/local/bin/easy_access.sh
    rm -r /usr/local/bin/kill.sh
    rm -r /usr/local/bin/killall.sh
    rm -r /usr/local/bin/server.sh
    rm -r /usr/local/bin/server_reload.sh
    rm -r /usr/bin/incuspeed
    systemctl disable --now incuspeed
    rm -r /usr/lib/systemd/system/incuspeed.service
fi
