BUILD_DIR=build
CFLAGS=-Wall -Wextra -pedantic -O2
LIB_PATH=../include
CLIBS=-I${LIB_PATH}

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/injectProgram ${BUILD_DIR}/reset ${BUILD_DIR}/pinonsame

${BUILD_DIR}/injectProgram: injectProgram.c $(LIB_PATH)/bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

${BUILD_DIR}/reset: reset.c $(LIB_PATH)/bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

${BUILD_DIR}/pinonsame: pinonsame.c $(LIB_PATH)/bpf_injection_msg.h
	$(CC) $(CFLAGS) $(CLIBS) $< -o $@

clean:
	-rm -f *.o ${BUILD_DIR}/*
