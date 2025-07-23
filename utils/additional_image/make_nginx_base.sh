#!/bin/bash
set -e

CONTAINER_NAME="nginx-ubuntu-2404"
IMAGE_ALIAS="nginx-1.24.0"
NGINX_VERSION="1.24.0-1ubuntu2"  # Adjust if exact version differs

# Launch base container from Ubuntu 24.04
echo "[+] Launching base container..."
incus launch images:ubuntu/24.04 "$CONTAINER_NAME"
sleep 10  # Wait for network to initialize

# Update APT and install pinned nginx version
echo "[+] Updating APT and installing nginx ${NGINX_VERSION}..."
incus exec "$CONTAINER_NAME" -- apt update
incus exec "$CONTAINER_NAME" -- apt install -y nginx=${NGINX_VERSION}

# Create APT pinning rule to keep this exact version
echo "[+] Creating APT pinning rule for nginx..."
incus exec "$CONTAINER_NAME" -- bash -c "cat > /etc/apt/preferences.d/nginx.pref <<EOF
Package: nginx
Pin: version ${NGINX_VERSION}
Pin-Priority: 1001
EOF"

# Optionally mark as held at dpkg level
echo "[+] Holding nginx via apt-mark..."
incus exec "$CONTAINER_NAME" -- apt-mark hold nginx

# Clean up APT cache to reduce image size
echo "[+] Cleaning up..."
incus exec "$CONTAINER_NAME" -- apt clean
incus exec "$CONTAINER_NAME" -- rm -rf /var/lib/apt/lists/*

# Stop container before publishing
echo "[+] Stopping container before publishing..."
incus stop "$CONTAINER_NAME"

# Publish container as reusable image
echo "[+] Publishing image '${IMAGE_ALIAS}'..."
incus publish "$CONTAINER_NAME" --alias "$IMAGE_ALIAS" \
  description="nginx ${NGINX_VERSION} (APT pinned) on Ubuntu 24.04"

echo "[+] Done."

