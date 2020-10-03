default: all

all: socketmain.c bpf_injection_msg.h reset.c
	gcc socketmain.c bpf_injection_msg.h -o socketmain
	gcc reset.c -o reset

clean:
	-rm -f socketmain
