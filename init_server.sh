#!/bin/bash
TAG="$1"
SERVER_IP="$(ip route get 1 | awk '{print $7}')"
echo -n "TAG: $TAG"
incus exec $TAG -- /prepare.sh
incus stop $TAG
