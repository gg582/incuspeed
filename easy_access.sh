#!/bin/bash
source /root/.bashrc
for i in $(incus list | awk '{print $2}');do incus exec $i /bin/bash;done

