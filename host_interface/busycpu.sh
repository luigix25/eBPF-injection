#!/bin/bash

taskset 0x00000001 yes > /dev/null &
taskset 0x00000002 yes > /dev/null &
taskset 0x00000004 yes > /dev/null &
taskset 0x00000008 yes > /dev/null &

echo "CPU 0, 1, 2, 3     busy with yes"
