#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>      
#include <time.h>
#include <sched.h>
#include "trace_helpers.h"


#include "bpf_injection_msg.h"

#include <linux/bpf.h>
#include "bpf_load.h"


//additional bpf libraries..
#include <bpf/bpf.h>

#include <bpf/libbpf.h>
#include "bpf_util.h"


#define IOCTL_SCHED_SETAFFINITY 13
#define IOCTL_PROGRAM_INJECTION_RESULT_READY 14

//affinity
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)

// Not needed. already declared in bpf_load.h automatically pick up
// All maps in order they are declared in bpf program file (their ELF sections)
/* values map */
// static int map_fd[1];


int saveToFile(const char* path, void* buf, unsigned int len);
struct bpf_injection_msg_t recv_bpf_injection_msg(int fd);
void print_cpu_set_mask(cpu_set_t* set);
void print_binary_mask(uint64_t value, int len);
void print_cpuset_array(cpu_set_t **set_array, int pCPU, int vCPU);

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

void print_cpuset_array(cpu_set_t **set_array, int pCPU, int vCPU){
	int i,j;
	printf("Affinity matrix. #pCPU:%d, #vCPU:%d\n", pCPU, vCPU);
	printf("pCPU→\t");
	for(i=0; i<pCPU; i++){
		printf("%d\t", i);
	}
	printf("\nvCPU↓\n\n");
	for(i=0; i<vCPU; i++){
		for(j=0; j<pCPU; j++){
			if(j==0){
				printf("    %d\t", i);
			}
			if(CPU_ISSET_S(j, SET_SIZE, set_array[i])){
				printf("1\t");
			}
			else{
				printf("0\t");
			}
			// printf("%d\t", matrix[i*MAX_CPU + j]);
			
		}
		printf("\n");
	}
}

void print_cpu_set_mask(cpu_set_t* set){
	int i;
	printf("CPU mask set on cpus:");
	for(i=0; i<MAX_CPU; i++){
        if(CPU_ISSET_S(i, SET_SIZE, set)){
            printf(" %d", i);
        }
    }
    printf("\n");
}

void print_binary_mask(uint64_t value, int len){	
	uint64_t flag;
	int i;
	if(len > 8){
		return;
	}
	for(i=0; i<(len*8); i++){
		flag = 1;
		flag = flag << i;
		if(value & flag){
			printf("1");			
		}
		else{
			printf("0");
		}		
	}
	printf("\n");	
}

struct bpf_injection_msg_t recv_bpf_injection_msg(int fd){
	struct bpf_injection_msg_t mymsg;
	int len, payload_left, offset;	
	mymsg.header.type = ERROR;

	// printf("Seek to offset 16 bytes..\n");
	if (lseek(fd, 16, SEEK_SET) < 0) {
	    perror("lseek: ");
	    return mymsg;
	}
	// printf("Seeked.\n");

	printf("Waiting for a bpf_message_header..\n");
	len = read(fd, &(mymsg.header), sizeof(struct bpf_injection_msg_header));
	if (len < 0) {
	    perror("read: ");
	    return mymsg;
	}
	printf("len:%d\n", len);
	print_bpf_injection_message(mymsg.header);

	printf("Allocating buffer for payload of %u bytes..\n", mymsg.header.payload_len);
	mymsg.payload = malloc(mymsg.header.payload_len);
	printf("Buffer allocated\n");

	printf("Current file offset is %ld\n", lseek(fd, 0, SEEK_CUR));

	printf("Seek to offset 20 bytes..\n");
	if (lseek(fd, 20, SEEK_SET) < 0) {
		perror("lseek: ");
		return mymsg;
	}
	printf("Seeked.\n");

	printf("Reading chunk by chunk..\n");

	offset = 0;
	payload_left = mymsg.header.payload_len;

	while(payload_left > 0){		
		len = read(fd, mymsg.payload + offset, 4);
		printf("Read offset %d\t0x%x\tread %d bytes\n", offset, *((unsigned int *)(mymsg.payload+offset)), len);
		if (len < 0) {
			perror("read: ");
			return mymsg;
		}
		offset += len;
		payload_left -= len;
	}

	printf("Received payload of %d bytes.\n", offset);
	return mymsg;
}


// To return informations to the device and then to the host, just write to device
// in order to trigger some action on the host side

int main(void){
	struct bpf_injection_msg_t mymsg;	
	cpu_set_t* set_array[MAX_CPU];
	int child_pid = -1;

	int fd = open("/dev/newdev", O_RDWR); 
	if (fd < 0) {
		perror("open: ");
	    return 1;
	}


	{
		int i;
		for(i=0; i<MAX_CPU;i++){
			set_array[i] = CPU_ALLOC(MAX_CPU);
			CPU_ZERO_S(SET_SIZE, set_array[i]);
		}
		// print_cpuset_array(set_array, 4, 4);
		// return 0;
	}



	// Read bpf_injection_message HOST -> GUEST

	while(1){
		mymsg = recv_bpf_injection_msg(fd);

		switch(mymsg.header.type){
			case PROGRAM_INJECTION:
				{
					int pid;

					printf("Writing bpf program to file..\n");
					if(saveToFile("./programs/mytestprog.o", mymsg.payload, mymsg.header.payload_len) > 0){
						return 1;
					}
					printf("bpf program successfully saved.\n");

					free(mymsg.payload);

					pid = fork();
					//error, no parent
					if(pid == -1){
						child_pid = -1;
						break;
					}
					//child
					else if(pid == 0){
						child_pid = 0;	//i am a child
					}
					//parent keep looping
					else{
						child_pid = pid;
						break;
					}


					printf("Loading bpf program...\n");
					//LOAD SUCH BPF PROGRAM
					if (load_bpf_file("./programs/mytestprog.o")) {
						printf("load_bpf_file error!\n");
						return 1;
					}
					printf("Bpf program successfully loaded.\n");

					// read_trace_pipe();

					printf("This is my values map fd:%d\n", map_fd[0]);
					//Wait some time.. then check how many sys_execve invocations and return
					sleep(1); //always used 20	
					// read_trace_pipe();

					// {
					// 	long value;
					// 	uint32_t index = 0;
					// 	bpf_map_lookup_elem(map_fd[0], &index, &value);
					// 	printf("sys_execve has been called for %ld times.\n", value);
					// }
					{
						uint64_t value = 0;
						uint32_t index = 0;
						int i;
						int val;
						cpu_set_t *set;
						struct timespec tim;
						int time_count = 0;
					    tim.tv_sec = 0;
					    tim.tv_nsec = 50000000L;    //50ms


					    // bpf_map_lookup_elem(map_fd[0], &index, &value);	
					    // printf("value is %lu\n", value);
					    // return 0;

						do{
							nanosleep(&tim, NULL);
							bpf_map_lookup_elem(map_fd[0], &index, &value);					
							if(time_count%5==0){
								// printf("timecount %d\tvalue=%lu\n", time_count, value);
							}
						} while(value == 0);

					    set = CPU_ALLOC(MAX_CPU);
					    memcpy(set, &value, SET_SIZE);
							
						printf("-----------\n");			
					    printf("BPF map modified. BPF probe on systemcall sched_setaffinity triggered.\n");
					    printf("A thread requested to tune his cpu affinity.\n");
					    print_cpu_set_mask(set);
					    printf("Binary mask: ");
					    print_binary_mask(value, 2);
					    if(value == 1 || value % 2 == 0){
					    	printf("cpu mask refers to one cpu only. cpu #%ld\n", value / 2);
					    }
					    else{
					    	printf("cpu mask refers to multiple cpus.\n");
					    }
					    printf("-----------\n");			

					    

					    print_cpuset_array(set_array, 4, 4);

					    memcpy(set_array[value/2], &value, sizeof(uint64_t));


						CPU_ZERO_S(SET_SIZE, set);
					    for(i=0; i<MAX_CPU;i++){
							if(i!=value/2){
								CPU_SET_S(i, SET_SIZE, set);
							}
						}
					    for(i=0; i<MAX_CPU; i++){
					    	if(i!=value/2){
					    		memcpy(set_array[i], set, SET_SIZE);
					    	}
					    }
					    print_cpuset_array(set_array, 4, 2);
					    // print_affinity_matrix(affinity_matrix, 8, 8);

					    val = value;
					    ioctl(fd, IOCTL_SCHED_SETAFFINITY, &val);


					    CPU_FREE(set);
					}
					break;
				}
			case PROGRAM_INJECTION_AFFINITY:					
				{				
					// struct cpu_affinity_infos_t myaffinityinfo;	
					// memcpy(&myaffinityinfo, mymsg.payload, mymsg.header.payload_len);
					// bool affinity_matrix[myaffinityinfo.n_pCPU*myaffinityinfo.n_vCPU];
					// memset(affinity_matrix, 1, myaffinityinfo.n_pCPU*myaffinityinfo.n_vCPU);
					// print_affinity_matrix(affinity_matrix, myaffinityinfo.n_pCPU, myaffinityinfo.n_vCPU);
				}
				break;
			default:
				printf("Unrecognized bpf_injection_message type (%d).\n", mymsg.header.type);
				break;

		}
	}



//-----------







	// END----- Read bpf_injection_message HOST -> GUEST


	// Response bpf_injection_msg  GUEST -> HOST


	// mymsg.payload = (void*) str;
	// mymsg.header.version = DEFAULT_VERSION;
	// mymsg.header.type = PROGRAM_INJECTION_RESULT;
	// mymsg.header.payload_len = 32;

	// print_bpf_injection_message(mymsg.header);


	// printf("Seek to offset 16 bytes..\n");
	// if (lseek(fd, 16, SEEK_SET) < 0) {
	//     perror("lseek: ");
	//     return 1;
	// }
	// printf("Seeked.\n");

	// printf("Write header\n");
	// len = write(fd, &(mymsg.header), sizeof(struct bpf_injection_msg_header));
	// if (len < 0) {
	//     perror("read: ");
	//     return 1;
	// }


	// offset = 0;
	// payload_left = mymsg.header.payload_len;

	// printf("Write chunk by chunk message payload..\n");
	// while(payload_left > 0){	
	// 	len = write(fd, mymsg.payload + offset, 4);
	// 	printf("Write chunk %d\n", offset/4);		
	// 	if (len < 0) {
	// 		perror("read: ");
	// 		return 1;
	// 	}
	// 	offset += len;
	// 	payload_left -= len;
	// }
	// printf("All %d chunks written. Total %d bytes.\n", offset/4, offset);

	// // Signal to device that response is ready
	// ioctl(fd, IOCTL_PROGRAM_INJECTION_RESULT_READY, NULL); // null argument

	// END----- Response bpf_injection_msg  GUEST -> HOST





	close(fd);
	return 0;
}