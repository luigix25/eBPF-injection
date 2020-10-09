default: all

all: injectProgram.c bpf_injection_msg.h reset.c pinonsame.c
	gcc injectProgram.c bpf_injection_msg.h -o injectProgram
	gcc reset.c bpf_injection_msg.h -o reset
	gcc pinonsame.c bpf_injection_msg.h -o pinonsame

clean:
	-rm -f socketmain reset pinonsame
