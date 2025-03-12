#!/bin/bash
TAG="$1"

# 안전한 비밀번호 설정 (예시: 사용자 입력)
read -p "Enter new password for root: " PASSWORD
echo "$PASSWORD" | openssl passwd -1 -stdin > /etc/shadow  # 직접 /etc/shadow 파일 수정 (더 안전)

# sshd_config 설정 추가 (기존 설정 유지)
cat <<EOF >> /etc/ssh/sshd_config
# Port 22 (표준 포트 사용)
# AddressFamily any
# ListenAddress 0.0.0.0
# ListenAddress ::
PubkeyAuthentication yes
# PermitRootLogin no (root 로그인 비활성화)
# PasswordAuthentication yes (비밀번호 인증 활성화, 필요에 따라 no로 변경 가능)
EOF

systemctl restart ssh

echo "SSH configured."
