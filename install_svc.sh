if [ $(whoami) = "root" ]
then
    cp -r incuspeed.service /usr/lib/systemd/system/incuspeed.service
    cd ..
    rm -r /usr/local/bin/incuspeed
    rm -r /usr/local/bin/conSSH.sh
    rm -r /usr/local/bin/easy_access.sh
    rm -r /usr/local/bin/killall.sh
    rm -r /usr/local/bin/kill.sh
    rm -r /usr/local/bin/server.sh
    rm -r /usr/local/bin/incuspeed
    echo  "Copying files..."
    mkdir /usr/local/bin/incuspeed
    cp -Rf incuspeed/* /usr/local/bin/incuspeed
    ln -s /usr/local/bin/incuspeed/*.sh /usr/local/bin
    ln -s /usr/local/bin/incuspeed/incuspeed /usr/local/bin
    systemctl daemon-reload
    systemctl enable --now incuspeed
    systemctl start  --now incuspeed
    echo "Done"
else
    sudo -s
fi
