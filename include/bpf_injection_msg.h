#pragma once
#include "bpf_injection_header.h"

void print_bpf_injection_message(struct bpf_injection_msg_header myheader){
	printf("  Version:%u\n  Type:%u\n  Payload_len:%u\n Service:%u\n", myheader.version, myheader.type, myheader.payload_len,myheader.service);
}