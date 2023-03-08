BUILD_DIR=build
CC=clang
CFLAGS= -O2 -Wall #-Wextra -pedantic

ARCH:=$(shell uname -m)

ifeq ($(ARCH),x86_64)
 TARGET=-D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
 TARGET=-D__TARGET_ARCH_arm64
endif

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/vcpu_pinning ${BUILD_DIR}/memory_swap ${BUILD_DIR}/firewall ${BUILD_DIR}/xdp

${BUILD_DIR}/vcpu_pinning: vcpu_pinning.c
	$(CC) $(CFLAGS) $(TARGET) -target bpf -g -c $< -o $@

${BUILD_DIR}/memory_swap: memory_swap.c
	$(CC) $(CFLAGS) $(TARGET) -target bpf -g -c $< -o $@

${BUILD_DIR}/firewall: firewall.c header.h
	$(CC) $(CFLAGS) $(TARGET) -target bpf -g -c $< -o $@

${BUILD_DIR}/xdp: xdp.c
	$(CC) $(CFLAGS) $(TARGET) -target bpf -c $< -o $@

clean:
	rm -f ${BUILD_DIR}/*

.PHONY: all clean
