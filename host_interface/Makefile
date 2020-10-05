default: all

all: socketmain.c bpf_injection_msg.h reset.c pinonsame.c
	gcc socketmain.c bpf_injection_msg.h -o socketmain
	gcc reset.c bpf_injection_msg.h -o reset
	gcc pinonsame.c bpf_injection_msg.h -o pinonsame

clean:
	-rm -f socketmain
