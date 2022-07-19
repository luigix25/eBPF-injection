PATH_LIB=/lib/modules/$(shell uname -r)
LINUXINCLUDE := -I${PATH_LIB}/build/include
BUILD_DIR=build
CC=clang

all: ${BUILD_DIR}/bpf_probe

${BUILD_DIR}/bpf_probe: myprog.c
	$(CC) -Wall $(LINUXINCLUDE) -D__TARGET_ARCH_x86 -O2 -target bpf -g -c $< -o $@

clean:
	rm -f build/*

.PHONY: all