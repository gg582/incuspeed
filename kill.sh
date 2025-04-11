#!/bin/bash


kill -9 $(pgrep linuxVirtualizationServer)
kill -9 $(pgrep server.sh)
incus stop $(incus list | awk '{print $2}' | sed '1,2d') --force
