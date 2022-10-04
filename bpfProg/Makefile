PATH_LIB_INCLUDE=/lib/modules/$(shell uname -r)
PATH_USR_INCLUDE=/usr/include/$(shell uname -m)-linux-gnu
LINUXINCLUDE := -I${PATH_LIB_INCLUDE}/build/include -I ${PATH_USR_INCLUDE} -I ../include
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

all: ${BUILD_DIR}/bpf_probe

${BUILD_DIR}/bpf_probe: myprog.c
	$(CC) $(CFLAGS) $(LINUXINCLUDE) $(TARGET) -target bpf -g -c $< -o $@

clean:
	rm -f ${BUILD_DIR}/*

.PHONY: all
