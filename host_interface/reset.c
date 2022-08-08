/*
 * Reset vCPU affinity (0xFFFFFFFFF) (affinity to all pCPU)
 * 2020 Giacomo Pellicci
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

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

// Message structure header+payload
#include <bpf_injection_msg.h>

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
  int len;
  
  mymsg.header.version = DEFAULT_VERSION;
  mymsg.header.type = RESET;
  mymsg.header.payload_len = sizeof(uint32_t);   
  mymsg.payload = malloc(sizeof(uint32_t));
  memset(mymsg.payload, 7, sizeof(uint32_t));

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

  // sleep(1);

  // Send eBPF message (program)
  send(sock, &(mymsg.header), sizeof(struct bpf_injection_msg_header), 0);

  send(sock, mymsg.payload, mymsg.header.payload_len, 0);
  free(mymsg.payload);

  // sleep(1);
  close (sock);
  // exit (EXIT_SUCCESS);
}