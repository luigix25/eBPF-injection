#!/bin/sh

set -ex

# Teardown.
rm /dev/newdev
rmmod driver
