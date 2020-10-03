#!/bin/sh

set -ex

# Teardown.
sudo rm /dev/newdev
sudo rmmod driver
