#pragma once

/*
*
*	Message structure used to exchange information between guest
*	and host during setup and execution phase of given eBPF programs.
*	Typical workflow is to have the host sending a message containing 
*	the eBPF program to be executed and then receive from guest a result
*	to be used in the specific scenario.
*
*/

/* type defines */
#define PROGRAM_INJECTION 						1
#define PROGRAM_INJECTION_RESULT 					2
#define PROGRAM_INJECTION_AFFINITY 					3
#define PROGRAM_INJECTION_AFFINITY_RESULT				4
#define SHUTDOWN_REQUEST						15
#define ERROR								16
#define RESET								17
#define PIN_ON_SAME							18
#define HT_REMAPPING							19
/* version defines */
#define DEFAULT_VERSION 					1

// +----+---------+------+----------------+
// | 0  | version | type | payload length |
// +----+---------+------+----------------+
// | 32 |                                 |
// +----+             payload             |
// | 64 |                                 |
// +----+---------------------------------+

struct bpf_injection_msg_header;
struct bpf_injection_msg_t;
void print_bpf_injection_message(struct bpf_injection_msg_header myheader);

struct bpf_injection_msg_header {
	uint8_t version;		//version of the protocol
	uint8_t type;			//what kind of payload is carried
	uint16_t payload_len;	//payload length
};

struct bpf_injection_msg_t {
	struct bpf_injection_msg_header header;
	void* payload;
};