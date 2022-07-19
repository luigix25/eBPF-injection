CC=gcc
BUILD_DIR=build
CFLAGS=-Wall -Wextra -pedantic -O2

default: all

all: injectProgram reset pinonsame


injectProgram: injectProgram.c bpf_injection_msg.h
	$(CC) $(CFLAGS) injectProgram.c bpf_injection_msg.h -o ${BUILD_DIR}/injectProgram

reset: reset.c bpf_injection_msg.h
	$(CC) $(CFLAGS) reset.c bpf_injection_msg.h -o ${BUILD_DIR}/reset

pinonsame: pinonsame.c bpf_injection_msg.h
	$(CC) $(CFLAGS) pinonsame.c bpf_injection_msg.h -o ${BUILD_DIR}/pinonsame

clean:
	-rm -f *.o ${BUILD_DIR}/*
