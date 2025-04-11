#!/bin/bash

set -e

IMAGES=(
    "ubuntu/24.04"
    "ubuntu/22.04"
    "ubuntu/20.04"
    "debian/12"
    "debian/11"
    "debian/10"
    "centos/9-Stream"
    "almalinux/9"
    "rockylinux/9"
    "devuan/chimaera"
    "devuan/daedalus"
    "devuan/beowulf"
    "archlinux/current"
    "slackware/current"
    "slackware/15.0"
)

container_count=1

for IMAGE in "${IMAGES[@]}"; do
    ALIAS=$(echo "$IMAGE" | tr '/' '-')
    container_name="tmp${container_count}"
    echo "Launching $container_name from image $IMAGE..."

    set -e
    trap 'echo "Error in $container_name with image $IMAGE" >> create_images.err.log' ERR

    incus launch images:"$IMAGE" "$container_name"
    sleep 1

    echo "Installing minimal packages in $container_name..."

    if incus exec "$container_name" -- grep -qi 'ubuntu\|debian\|devuan' /etc/os-release; then
        incus exec "$container_name" -- sh -c "apt-get update -y"
        incus exec "$container_name" -- sh -c "apt-get install -y --no-install-recommends openssh-server openssh-client gnupg2 sudo"

    elif incus exec "$container_name" -- grep -qi 'centos\|almalinux\|rocky' /etc/os-release; then
        incus exec "$container_name" -- sh -c "dnf clean all"
        incus exec "$container_name" -- sh -c "dnf update -y"
        incus exec "$container_name" -- sh -c "dnf install -y --setopt=install_weak_deps=False gnupg2 openssh-server openssh-clients sudo"
        incus exec "$container_name" -- sh -c "rpm --import /etc/pki/rpm-gpg/*" || true

    elif incus exec "$container_name" -- grep -qi 'arch' /etc/os-release; then
        incus exec "$container_name" -- sh -c "pacman -Sy --noconfirm archlinux-keyring"
        incus exec "$container_name" -- sh -c "pacman-key --init"
        incus exec "$container_name" -- sh -c "pacman-key --populate"
        incus exec "$container_name" -- sh -c "pacman -Syu --noconfirm openssh sudo" || {
            incus exec "$container_name" -- sh -c "pacman -Syy --noconfirm"
            incus exec "$container_name" -- sh -c "pacman -S openssh --noconfirm"
        }

    elif incus exec "$container_name" -- grep -qi 'amzn' /etc/os-release; then
        incus exec "$container_name" -- sh -c "yum update -y"
        incus exec "$container_name" -- sh -c "yum install -y openssh-server openssh-clients sudo"
        incus exec "$container_name" -- sh -c "rpm --import /etc/pki/rpm-gpg/*" || true

    elif incus exec "$container_name" -- grep -qi 'slackware' /etc/os-release; then
        incus exec "$container_name" -- sh -c "echo BATCH=on >> /etc/slackpkg/slackpkg.conf"
        incus exec "$container_name" -- sh -c "echo DEFAULT_ANSWER=y >> /etc/slackpkg/slackpkg.conf"
        incus exec "$container_name" -- sh -c "slackpkg clean-cache"
        incus exec "$container_name" -- sh -c "slackpkg update"
        incus exec "$container_name" -- sh -c "slackpkg update gpg"
        incus exec "$container_name" -- sh -c "slackpkg install openssh sudo"
        incus exec "$container_name" -- sh -c "sed -i '\$d' /etc/slackpkg/slackpkg.conf" 
        incus exec "$container_name" -- sh -c "sed -i '\$d' /etc/slackpkg/slackpkg.conf" 

    else
        echo "Unknown distro in $IMAGE, skipping."
        incus stop "$container_name" --force
        incus delete "$container_name" --force
        exit 1
    fi

    incus file push -r /usr/local/bin/linuxVirtualization/conSSH.sh "$container_name"/
    echo "Publishing $container_name as image with alias $ALIAS..."
    incus stop "$container_name" --force
    incus publish "$container_name" --alias "$ALIAS" --public

    echo "Cleaning up temporary container $container_name..."
    incus delete "$container_name" --force
    echo "Finished creating image: $ALIAS"

    ((container_count++))
done

echo "All image creation processes finished."
