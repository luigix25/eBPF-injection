CC=gcc
BUILD_DIR=build
CFLAGS=-Wall -Wextra -pedantic -O2

all: ${BUILD_DIR}/injectProgram ${BUILD_DIR}/reset ${BUILD_DIR}/pinonsame


${BUILD_DIR}/injectProgram: injectProgram.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $< -o $@

${BUILD_DIR}/reset: reset.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $< -o $@

${BUILD_DIR}/pinonsame: pinonsame.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	-rm -f *.o ${BUILD_DIR}/*
