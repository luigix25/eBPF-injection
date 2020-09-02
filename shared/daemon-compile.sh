#!/usr/bin/env bash

set -eux

rm -rf /home/giacomo/Desktop/tesi/linux/samples/bpf/mymain.c
cp /home/giacomo/myvm/shared/test/mymain.c /home/giacomo/Desktop/tesi/linux/samples/bpf/mymain.c
cd /home/giacomo/Desktop/tesi/linux
make M=samples/bpf

cp samples/bpf/mymain /home/giacomo/myvm/shared/test