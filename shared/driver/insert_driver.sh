#!/bin/sh

set -ex

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"
# Setup. (ins kernel module, create device file at /dev/newdev)
sudo insmod driver.ko
sudo ./mknoddev.sh newdev
