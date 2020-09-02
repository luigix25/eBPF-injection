#!/usr/bin/env bash

set -eux

# Parameters.
id=ubuntu-20.04-live-server-amd64 #ubuntu-18.04.1-desktop-amd64
disk_img="${id}.img.qcow2"
disk_img_snapshot="${id}.snapshot.qcow2"
iso="${id}.iso"

# Get image.
if [ ! -f "$iso" ]; then
  wget "http://releases.ubuntu.com/20.04/${iso}"
fi

# Go through installer manually.
if [ ! -f "$disk_img" ]; then
  qemu-img create -f qcow2 "$disk_img" 1T
  qemu-system-x86_64 \
    -cdrom "$iso" \
    -drive "file=${disk_img},format=qcow2" \
    -enable-kvm \
    -m 2G \
    -smp 2 \
  ;
fi

# Snapshot the installation.
if [ ! -f "$disk_img_snapshot" ]; then
  qemu-img \
    create \
    -b "$disk_img" \
    -f qcow2 \
    "$disk_img_snapshot" \
  ;
fi

#   -vga virtio \
# /home/giacomo/Desktop/tesi/qemu/build/x86_64-softmmu/qemu-system-x86_64
# Run the installed image.
/home/giacomo/Desktop/tesi/qemu/build/x86_64-softmmu/qemu-system-x86_64 \
  -drive "file=${disk_img_snapshot},format=qcow2" \
  -enable-kvm \
  -m 2G \
  -smp 2 \
  -nographic \
  -device virtio-net-pci,netdev=ssh \
  -netdev user,id=ssh,hostfwd=tcp::2222-:22 \
  -virtfs local,id=sfs,path=shared,security_model=passthrough,mount_tag=shared \
  -device newdev 
  "$@" \
;
