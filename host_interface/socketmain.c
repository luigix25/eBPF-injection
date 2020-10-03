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

// Message structure header+payload
#include "bpf_injection_msg.h"

#define PORT            9999
#define SERVERHOST      "localhost"

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


int main (void){
  int sock;
  struct sockaddr_in servername;
  struct bpf_injection_msg_t mymsg;
  struct cpu_affinity_infos_t myaffinityinfo;
  int len;

  mymsg = prepare_bpf_injection_message("/home/giacomo/myvm/data/mytestprog.o");
  printf("bpf injection message prepared.\n");
  print_bpf_injection_message(mymsg.header);

  /* Create the socket. */
  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("socket (client)");
      exit (EXIT_FAILURE);
    }
    printf("socket created\n");

  /* Connect to the server. */
  init_sockaddr (&servername, SERVERHOST, PORT);
  if (connect (sock, (struct sockaddr *) &servername, sizeof (servername)) < 0){
      perror ("connect (client)");
      exit (EXIT_FAILURE);
  }
  printf("socket connected\n");

  sleep(2);



  // len = recv(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);
  // if(len <= 0){
  //     printf("len <0 error\n");
  //     return 1;
  // }
  // print_bpf_injection_message(mymsg.header);   

  // mymsg.payload = malloc(32);

  // len = recv(sock, mymsg.payload, 32, 0);
    
  // printf("Payload:%s\n", (char*)mymsg.payload); 

  // return 0;

  // Send eBPF message (program)
  send(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);

  send(sock, mymsg.payload, mymsg.header.payload_len, 0);
  free(mymsg.payload);


  // // sleep(3);

  // //Send cpu affinity infos
  // printf("This system[host] has %d cpus\n", get_nprocs());
  // //Assume in this scenario to have n_pCPU >= n_vCPU   [not so smart to set affinity in overbooked system]
  // myaffinityinfo.n_pCPU = get_nprocs();
  // myaffinityinfo.n_vCPU = myaffinityinfo.n_pCPU;  //Allocate up to pCPU = n_vCPU  

  
  // mymsg.header.version = DEFAULT_VERSION;
  // mymsg.header.type = PROGRAM_INJECTION_AFFINITY;
  // mymsg.header.payload_len = sizeof(struct cpu_affinity_infos_t);
  // mymsg.payload = &myaffinityinfo;

  // send_bpf_injection_message(sock, mymsg);



  sleep(5);
  close (sock);
  // exit (EXIT_SUCCESS);
}