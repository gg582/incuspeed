#!/bin/bash
kill -9 $(pgrep server)
kill -9 $(pgrep server.sh)
source /root/.bashrc
echo -n > container/latest_access
sudo rm -rf nohup*.out
kill -9 `pgrep init_server`
systemctl restart --now nginx
