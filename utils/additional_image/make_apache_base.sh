#!/bin/bash
set -e

CONTAINER_NAME="apache2-ubuntu-2404"
IMAGE_ALIAS="apache2-2.4.58"
APACHE_VERSION="2.4.58-1ubuntu3"

# Launch base container
echo "[+] Launching Ubuntu 24.04 container..."
incus launch images:ubuntu/24.04 "$CONTAINER_NAME"

# Wait for network
sleep 10

# Update & install specific version of apache2
incus exec "$CONTAINER_NAME" -- apt update
incus exec "$CONTAINER_NAME" -- apt install -y apache2=$APACHE_VERSION

# Clean up
incus exec "$CONTAINER_NAME" -- apt clean
incus exec "$CONTAINER_NAME" -- rm -rf /var/lib/apt/lists/*

# Stop and publish
incus stop "$CONTAINER_NAME"
incus publish "$CONTAINER_NAME" --alias "$IMAGE_ALIAS" description="Apache $APACHE_VERSION on Ubuntu 24.04"
echo "[+] Done: $IMAGE_ALIAS"

