#!/bin/bash
set -e

CONTAINER_NAME="python312-debian12"
IMAGE_ALIAS="python-3.12.3"

incus launch images:debian/12 "$CONTAINER_NAME"
sleep 10

# Install dependencies and build Python from source
incus exec "$CONTAINER_NAME" -- apt update
incus exec "$CONTAINER_NAME" -- apt install -y wget build-essential libssl-dev zlib1g-dev \
  libncurses-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev

# Download & build Python 3.12.3
incus exec "$CONTAINER_NAME" -- bash -c "
cd /usr/src && \
wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz && \
tar xzf Python-3.12.3.tgz && cd Python-3.12.3 && \
./configure --enable-optimizations && make -j\$(nproc) && make altinstall
"

# Clean up
incus exec "$CONTAINER_NAME" -- rm -rf /usr/src/Python*
incus exec "$CONTAINER_NAME" -- apt clean

# Stop & publish
incus stop "$CONTAINER_NAME"
incus publish "$CONTAINER_NAME" --alias "$IMAGE_ALIAS" description="Python 3.12.3 on Debian 12"
echo "[+] Done: $IMAGE_ALIAS"

