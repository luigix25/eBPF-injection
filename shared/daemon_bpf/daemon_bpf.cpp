/*
 * BPF guest daemon
 * 2022 Luigi Leonardi
 * Based on the previous work by Giacomo Pellicci
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

//#define _GNU_SOURCE
//#include <unistd.h>
//#include <stdlib.h>
#include <fcntl.h>
//#include <sched.h>

#include <sys/mman.h>
//#include <sys/stat.h>
#include <sys/ioctl.h> 
#include <sys/syscall.h>


#include <iostream>
#include <bitset>
#include <cerrno>
#include <csignal>
#include <ctime>

using namespace std;

#include <bpf_injection_msg.h>
#include "BpfLoader.h"

#define DEBUG

#ifdef DEBUG
    #define DBG(x) x 
#else
    #define DBG(x)
#endif


//TODO: spostare?
#define MAX_CPU 64

// To return informations to the device and then to the host, just write to device
// in order to trigger some action on the host side

bpf_injection_msg_t recv_bpf_injection_msg(int fd){
    #warning togliere le varie seek
	bpf_injection_msg_t mymsg;
	int32_t len, payload_left;	
	mymsg.header.type = ERROR;

	cout<<"Seek to offset 16 bytes.."<<endl;
	if (lseek(fd, 16, SEEK_SET) < 0) {
	    perror("lseek: ");
	    return mymsg;
	}
	cout<<"Seeked."<<endl;

	cout<<"Waiting for a bpf_message_header.."<<endl;
	len = read(fd, &(mymsg.header), sizeof(bpf_injection_msg_header));
	if (len < 0) {
	    perror("read: ");
	    return mymsg;
	}

	print_bpf_injection_message(mymsg.header);

	cout<<"Allocating buffer for payload of "<<mymsg.header.payload_len<<" bytes.."<<endl;
	mymsg.payload = new uint8_t[mymsg.header.payload_len];
	cout<<"Buffer allocated"<<endl;

	cout<<"Current file offset is "<<lseek(fd, 0, SEEK_CUR)<<endl;

	cout<<"Reading chunk by chunk.."<<endl;
	payload_left = mymsg.header.payload_len;
    uint8_t *addr = static_cast<uint8_t*>(mymsg.payload);

	while(payload_left > 0){	
        	
		len = read(fd, addr, 4);
		if (len < 0) {
			perror("read: ");
			return mymsg;
		}
		addr += len;
		payload_left -= len;
	}

	cout<<"Received payload of "<<mymsg.header.payload_len<<" bytes."<<endl;
	return mymsg;
}

int handleProgramInjection(bpf_injection_msg_t message){

    BpfLoader loader(message);
    int map_fd = loader.loadAndGetMap();
    if(map_fd < 0){
        return -1;
    }

    cout<<"[LOG] Starting operations"<<endl;

    timespec time_period;
    time_period.tv_sec = 0;
    time_period.tv_nsec = 50000000L;    //50ms

    while(true){
        nanosleep(&time_period, NULL);  //sleeping
        
        uint32_t index = 0;
        uint64_t n_modified; //each row is 64 bits
        bpf_map_lookup_elem(map_fd,&index,&n_modified); //first elem is the pos. of first free slot

        if(n_modified == 0)
            continue; //no changes in BPF map

        cout<<"BPF Map Modified: number of changes "<<n_modified<<endl;

        for (uint32_t i=1; i <= n_modified && i < MAX_CPU; i++){

            uint64_t cpu_mask;
            bpf_map_lookup_elem(map_fd,&i,&cpu_mask);
            
            DBG(

                bitset<64> cpu_bitmask(cpu_mask);
                cout<<cpu_bitmask<<endl;

                if(__builtin_popcountll(cpu_mask) > 1)
                    cout<<"Pinning to more than 1 CPU"<<endl;
                else
                    cout<<"Pinning to one CPU"<<endl;
                
                cout<<"------------"<<endl;

            );

            #warning valore passato per riferimento ad ioctl
            #warning abilitare ioctl
            //ioctl(fd, IOCTL_SCHED_SETAFFINITY, &value);
            cpu_mask = 0;
            bpf_map_update_elem(map_fd, &i, &cpu_mask, BPF_ANY);
        }

        //resetting first slot
        n_modified = 0;
        bpf_map_update_elem(map_fd, &index, &n_modified, BPF_ANY);

    }
}

int main(){

    cout<<"[LOG] Starting Guest Agent"<<endl;
	
    int fd = open("/dev/newdev",O_RDWR);
    if(fd < 0){
        cout<<"Error while opening device"<<endl;
        return -1;
    }

    pid_t pid, child_pid;
    child_pid = -1;

    while(true){

        bpf_injection_msg_t message = recv_bpf_injection_msg(fd);

        pid = fork();
        if(pid == -1){
            cerr<<"Fork failed\n";
            exit(-1);
        } else if(pid != 0){            //parent
            if(child_pid != -1){
                cout<<"[LOG] Killing Old BPF Program"<<endl;
                kill(child_pid, SIGKILL);
            }

            child_pid = pid;
            //Parent keeps listening for new messages
            continue;
        }

        //Parent will never reach here.
        //Child will handle the injection

        switch (message.header.type){
            case PROGRAM_INJECTION:
                if(handleProgramInjection(message) < 0){
                    cerr<<"Generic Error"<<endl;
                    return -1;
                }
                break;
            
            default:
                cout<<"Unrecognized Payload Type: 0x"<<hex<<message.header.type<<"\n";
                break;
        }
    }


    //cleanup
    close(fd);

	return 0;

}