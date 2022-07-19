BUILD_DIR=build

default: all

all: injectProgram reset pinonsame


injectProgram: injectProgram.c bpf_injection_msg.h
	gcc injectProgram.c bpf_injection_msg.h -o ${BUILD_DIR}/injectProgram

reset: reset.c bpf_injection_msg.h
	gcc reset.c bpf_injection_msg.h -o ${BUILD_DIR}/reset

pinonsame: pinonsame.c bpf_injection_msg.h
	gcc pinonsame.c bpf_injection_msg.h -o ${BUILD_DIR}/pinonsame

clean:
	-rm -f *.o ${BUILD_DIR}/*
