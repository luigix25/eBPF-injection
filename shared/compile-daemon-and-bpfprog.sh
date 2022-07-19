#!/usr/bin/env bash

path_to_linux=/home/luigi/Desktop/pellicci/linux-5.10
path_to_source=/home/luigi/Desktop/pellicci/eBPF-injection

set -eux

rm -rf $path_to_linux/samples/bpf/myprog.c
rm -rf $path_to_linux/samples/bpf/daemon_bpf.c
cp $path_to_source/bpfProg/myprog.c $path_to_linux/samples/bpf/myprog.c
cp $path_to_source/shared/daemon_bpf/daemon_bpf.c $path_to_linux/samples/bpf/daemon_bpf.c
cp $path_to_source/shared/daemon_bpf/bpf_injection_msg.h $path_to_linux/samples/bpf/bpf_injection_msg.h
cd $path_to_linux
make M=samples/bpf

cp samples/bpf/myprog.o $path_to_source/bpfProg/mytestprog.o
cp $path_to_linux/samples/bpf/daemon_bpf $path_to_source/shared/daemon_bpf/daemon_bpf
chmod 755 $path_to_source/shared/daemon_bpf/daemon_bpf
