#!/bin/sh

set -ex

# Setup. (ins kernel module, create device file at /dev/newdev)
sudo insmod driver.ko
sudo ./mknoddev.sh newdev
