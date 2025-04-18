#!/bin/bash

incus image list --format csv | tail -n +1 | awk -F',' '{alias=$1; fingerprint=$2; if (alias != "") printf "\ \ \ \ \"%s\": \"%s\",\n", alias, fingerprint}' > temp_map.txt

echo "package incus_unit

var baseImages = map[string]string{
$(cat temp_map.txt)
}" > linux_virt_unit/incus_unit/base_images.go

rm temp_map.txt

echo "base_images.go 파일 생성 완료"
