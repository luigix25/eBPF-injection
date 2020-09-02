#!/bin/sh

set -ex

# Setup. (ins kernel module, create device file at /dev/newdev)
insmod driver.ko
./mknoddev.sh newdev
