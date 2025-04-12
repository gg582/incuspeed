if [ $(whoami) = "root" ]
then
    cp -r linuxVirtualization.service /usr/lib/systemd/system/linuxVirtualization.service
    cd ..
    rm -r /usr/local/bin/linuxVirtualization
    rm -r /usr/local/bin/conSSH.sh
    rm -r /usr/local/bin/easy_access.sh
    rm -r /usr/local/bin/killall.sh
    rm -r /usr/local/bin/kill.sh
    rm -r /usr/local/bin/server.sh
    rm -r /usr/local/bin/linuxVirtualizationServer
    echo  "Copying files..."
    mkdir /usr/local/bin/linuxVirtualization
    cp -Rf linuxVirtualization/* /usr/local/bin/linuxVirtualization
    ln -s /usr/local/bin/linuxVirtualization/*.sh /usr/local/bin
    ln -s /usr/local/bin/linuxVirtualization/linuxVirtualiztionServer /usr/local/bin
    systemctl daemon-reload
    systemctl enable --now linuxVirtualization
    systemctl start  --now linuxVirtualization
    echo "Done"
else
    sudo -s
fi
