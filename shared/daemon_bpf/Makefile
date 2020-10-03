default: all

all: daemon_bpf.c bpf_injection_msg.h
	gcc daemon_bpf.c bpf_injection_msg.h -o daemon_bpf

clean:
	-rm -f daemon_bpf