#!/bin/bash
if [ "$(whoami)" == "root" ]
then
    rm -r /usr/local/bin/linuxVirtualization
    rm -r /usr/local/bin/apply_nginx.sh
    rm -r /usr/local/bin/clean.sh
    rm -r /usr/local/bin/conSSH.sh
    rm -r /usr/local/bin/container_creation.sh
    rm -r /usr/local/bin/delete_container.sh
    rm -r /usr/local/bin/easy_access.sh
    rm -r /usr/local/bin/remove-service.sh
    rm -r /usr/local/bin/add_port.sh
    rm -r /usr/local/bin/init_server.sh
    rm -r /usr/local/bin/initial_setup.sh
    rm -r /usr/local/bin/install_svc.sh
    rm -r /usr/local/bin/kill.sh
    rm -r /usr/local/bin/prepare.sh
    rm -r /usr/local/bin/server.sh
    rm -r /usr/local/bin/server_reload.sh
    rm -r /usr/local/bin/server
    rm -r /usr/local/bin/start.sh
    rm -r /usr/local/bin/stop.sh
    rm -r '/usr/local/bin/*.sh'
    systemctl disable --now linuxVirtualization
    rm -r /usr/lib/systemd/system/linuxVirtualization.service
fi
