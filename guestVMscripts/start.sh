#!/usr/bin/env bash

# This script does the following:
# 	1	mount the shared folder
# 	2 	build device driver
# 	3	insmod driver
# 	4	places you in shared folder

sudo ./mountscript.sh
cd shared/driver
make
sudo ./insert_driver.sh
cd ..
