#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/sysinfo.h>

#include <sched.h>
#include <string.h>
#include <time.h> 
// Message structure header+payload
#include "bpf_injection_msg.h"

#define PORT            9999
#define SERVERHOST      "localhost"
#define ONE_SECOND_IN_NANOSECOND 1000000000L

void init_sockaddr (struct sockaddr_in *name, const char *hostname, uint16_t port){
	struct hostent *hostinfo;

	name->sin_family = AF_INET;
	name->sin_port = htons (port);
	hostinfo = gethostbyname (hostname);
	if (hostinfo == NULL)
	{
		fprintf (stderr, "Unknown host %s.\n", hostname);
		exit (EXIT_FAILURE);
	}
	name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}

int saveToFile(const char* path, void* buf, unsigned int len){
	FILE *f;
	f = fopen(path, "w");
	if(f == NULL){
		printf("saveToFile: WRONG FOPEN\n");
		return 1;
	}

	if(fwrite(buf, 1, len, f) != len){
		printf("saveToFile: WRONG FWRITE\n");
		return 1;
	}

	if(fclose(f) != 0){
		printf("saveToFile: WRONG FCLOSE\n");
		return 1;
	}

	return 0;
}

void send_bpf_injection_message(int sock, struct bpf_injection_msg_t mymsg){
	send(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);

	send(sock, mymsg.payload, mymsg.header.payload_len, 0);
}


int main (int argc, char* argv[]){
	int sock;
	struct sockaddr_in servername;
	struct bpf_injection_msg_t mymsg;
	struct cpu_affinity_infos_t myaffinityinfo;
	int len;
	int test_duration_sec;
	long long int serial_time;
	struct timespec tim;


	if(argc != 3){
		printf("./pinonsame <percentage> <total duration>\n");
		return -1;
	}

	if(atoi(argv[1]) <= 0){
		printf("percentage <= 0, returning immediately\n");
		return 0;
	}

	test_duration_sec = atoi(argv[2]);

	mymsg.header.version = DEFAULT_VERSION;
	mymsg.header.type = PIN_ON_SAME;
	mymsg.header.payload_len = sizeof(uint32_t);   
	mymsg.payload = malloc(sizeof(uint32_t));
	memset(mymsg.payload, 0, sizeof(uint32_t));

  /* Create the socket. */
	sock = socket (PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror ("socket (client)");
		exit (EXIT_FAILURE);
	}
	// printf("socket created\n");

  /* Connect to the server. */
	init_sockaddr (&servername, SERVERHOST, PORT);
	if (connect (sock, (struct sockaddr *) &servername, sizeof (servername)) < 0){
		perror ("connect (client)");
		exit (EXIT_FAILURE);
	}
	// printf("socket connected\n");

  // Send eBPF message (pinonsame)
	send(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);

	send(sock, mymsg.payload, mymsg.header.payload_len, 0);
	free(mymsg.payload);

  // Compute serialization time
   
	serial_time = ONE_SECOND_IN_NANOSECOND * test_duration_sec * atoi(argv[1]) / 100; 	//in nanoseconds
	tim.tv_sec = serial_time/ ONE_SECOND_IN_NANOSECOND;
	tim.tv_nsec = serial_time % ONE_SECOND_IN_NANOSECOND;
	if(nanosleep(&tim , NULL) < 0 )   
	{
		printf("Nano sleep system call failed \n");
		return -1;
	}


// Send eBPF message (reset)

	mymsg.header.type = RESET;
	mymsg.payload = malloc(sizeof(uint32_t));
	memset(mymsg.payload, 7, sizeof(uint32_t));

	send(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);

	send(sock, mymsg.payload, mymsg.header.payload_len, 0);
	free(mymsg.payload);

	close (sock);
  // exit (EXIT_SUCCESS);
}