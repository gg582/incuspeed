#!/bin/bash
set -e

CONTAINER_NAME="jdk17-ubuntu2204"
IMAGE_ALIAS="openjdk-17"

incus launch images:ubuntu/22.04 "$CONTAINER_NAME"
sleep 10

# Install pinned OpenJDK version
incus exec "$CONTAINER_NAME" -- apt update
incus exec "$CONTAINER_NAME" -- apt install -y openjdk-17-jdk=17.0.11+9-1~22.04

# Clean up
incus exec "$CONTAINER_NAME" -- apt clean
incus exec "$CONTAINER_NAME" -- rm -rf /var/lib/apt/lists/*

# Stop & publish
incus stop "$CONTAINER_NAME"
incus publish "$CONTAINER_NAME" --alias "$IMAGE_ALIAS" description="OpenJDK 17 on Ubuntu 22.04"
echo "[+] Done: $IMAGE_ALIAS"

