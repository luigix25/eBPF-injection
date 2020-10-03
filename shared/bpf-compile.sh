#!/usr/bin/env bash

set -eux

rm -rf /home/giacomo/Desktop/tesi/linux/samples/bpf/myprog.c
cp /home/giacomo/myvm/data/myprog.c /home/giacomo/Desktop/tesi/linux/samples/bpf/myprog.c
cd /home/giacomo/Desktop/tesi/linux
make M=samples/bpf

sudo cp samples/bpf/myprog.o /home/giacomo/myvm/shared/test/programs/mytestprog.o
sudo cp samples/bpf/myprog.o /home/giacomo/myvm/data/mytestprog.o