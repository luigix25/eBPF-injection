CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2

default: all

all: daemon_bpf.c bpf_injection_msg.h
	$(CC) $(CFLAGS) daemon_bpf.c bpf_injection_msg.h -o daemon_bpf

clean:
	-rm -f daemon_bpf