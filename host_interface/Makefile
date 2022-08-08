BUILD_DIR=build
CFLAGS=-Wall -Wextra -pedantic -O2
CLIBS=-I../include

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/injectProgram ${BUILD_DIR}/reset ${BUILD_DIR}/pinonsame

${BUILD_DIR}/injectProgram: injectProgram.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

${BUILD_DIR}/reset: reset.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

${BUILD_DIR}/pinonsame: pinonsame.c bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

clean:
	-rm -f *.o ${BUILD_DIR}/*
