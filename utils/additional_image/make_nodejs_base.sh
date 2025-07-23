#!/bin/bash
set -e

CONTAINER_NAME="node20-ubuntu2204"
IMAGE_ALIAS="nodejs-20"

incus launch images:ubuntu/22.04 "$CONTAINER_NAME"
sleep 10

# Install Node.js v20 from nodesource
incus exec "$CONTAINER_NAME" -- apt update
incus exec "$CONTAINER_NAME" -- apt install -y curl
incus exec "$CONTAINER_NAME" -- curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
incus exec "$CONTAINER_NAME" -- apt install -y nodejs

# Pin version (optional)
incus exec "$CONTAINER_NAME" -- bash -c "echo 'nodejs hold' | dpkg --set-selections"

# Clean up
incus exec "$CONTAINER_NAME" -- apt clean

# Stop & publish
incus stop "$CONTAINER_NAME"
incus publish "$CONTAINER_NAME" --alias "$IMAGE_ALIAS" description="Node.js v20 on Ubuntu 22.04"
echo "[+] Done: $IMAGE_ALIAS"

