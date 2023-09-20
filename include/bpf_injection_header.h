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
#define PROGRAM_INJECTION 							1
#define PROGRAM_INJECTION_ACK						2
#define PROGRAM_INJECTION_RESULT					3
#define SHUTDOWN_REQUEST							15
#define ERROR										16
#define RESET										17
#define PIN_ON_SAME									18
#define HT_REMAPPING								19
/* version defines */
#define DEFAULT_VERSION 							1

#define IOCTL_SCHED_SETAFFINITY 13
#define IOCTL_PROGRAM_RESULT_READY 14

#define INJECTION_OK 	0
#define INJECTION_FAIL 	1

/* version define */
#define DEFAULT_VERSION 					1

//TODO: update ascii art

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
	uint8_t service;		//VCPU_PINNING_TYPE, DYNAMIC_MEM_TYPE[..]
	uint16_t payload_len;	//payload length
} __attribute__((__packed__));

struct bpf_injection_ack {
	uint8_t status; //INJECTION_OK, INJECTION_FAIL
};

struct bpf_injection_msg_t {
	struct bpf_injection_msg_header header;
	void* payload;
};

struct bpf_event_t {
	uint64_t type;
	uint64_t size;
	void *payload;
};