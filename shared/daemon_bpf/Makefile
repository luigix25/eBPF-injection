CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2
BUILD_DIR=build

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/daemon_bpf

${BUILD_DIR}/daemon_bpf: ${BUILD_DIR}/daemon_bpf.o ${BUILD_DIR}/bpf_load.o
	$(CC) $(CFLAGS) $^ -lbpf -lelf -o $@ 

${BUILD_DIR}/daemon_bpf.o: daemon_bpf.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $< -c -o $@

${BUILD_DIR}/bpf_load.o: bpf_load.c bpf_load.h
	$(CC) $(CFLAGS) $< -c -o $@


clean:
	-rm -f ${BUILD_DIR}/*