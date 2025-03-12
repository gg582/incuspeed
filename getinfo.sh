#!/bin/bash
/snap/bin/incus list | grep $1 | awk '{print $4}' 
