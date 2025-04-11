#!/bin/bash
USERNAME="$1"
PASSWORD="$2"
TAG="$3"
useradd -m -s /bin/bash $USERNAME
usermod -aG sudo $USERNAME
echo -n "$USERNAME:$PASSWORD" > /tmp/passfile
chpasswd < /tmp/passfile
echo "$USERNAME ALL=(ALL:ALL) ALL" >> /etc/sudoers

rm -rf /etc/ssh/sshd_config
rm -rf /tmp/passfile
# sshd_config 설정 추가 (기존 설정 유지)
cat <<EOF >> /etc/ssh/sshd_config
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
PubkeyAuthentication yes
PermitRootLogin no
PasswordAuthentication yes 
EOF

if ! test -f /usr/bin/systemctl;
then
    if test -d /etc/rc.d;
    then
        /etc/rc.d/rc.sshd restart
    elif test -d /etc/init.d;
    then
        /etc/init.d/ssh restart
    else
        /etc/*.d/*ssh* restart
    fi
else
    systemctl restart sshd
    systemctl restart ssh
fi

echo "SSH configured."
