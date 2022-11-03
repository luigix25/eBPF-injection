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

// To return informations to the device and then to the host, just write to device
// in order to trigger some action on the host side

bpf_injection_msg_t recv_bpf_injection_msg(int fd){
	bpf_injection_msg_t mymsg;
	int32_t len, payload_left;	
	mymsg.header.type = ERROR;

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

	cout<<"Reading chunk by chunk.."<<endl;
	payload_left = mymsg.header.payload_len;
    uint8_t *addr = static_cast<uint8_t*>(mymsg.payload);

	while(payload_left > 0){	
        	
		len = read(fd, addr, payload_left);
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

int handler_ringbuf(void *ctx, void *data, size_t){
    /* Each time a new element is available in the ringbuffer this function is called */
    bpf_event_t *event = static_cast<bpf_event_t*>(data);

    //For debug
    //uint64_t *ptr = (uint64_t*)&event->payload;
        
    int dev_fd = reinterpret_cast<long>(ctx);

    if(write(dev_fd,data,event->size + 2*sizeof(uint64_t)) == -1){ //Type and Payload
        cout<<"Can't write to the device\n";
        return -1;
    }
    int one = 1;
    ioctl(dev_fd, IOCTL_PROGRAM_RESULT_READY, &one);

    return 0;

}

int handleProgramInjection(bpf_injection_msg_t message, int dev_fd){

    BpfLoader loader(message);
    int map_fd = loader.loadAndGetMap();
    if(map_fd < 0){
        cout<<"Map Not Found"<<endl;
        return -1;
    }

    ring_buffer *buffer_bpf = ring_buffer__new(map_fd,handler_ringbuf,(void*)(long)dev_fd,NULL);
    cout<<"[LOG] Starting operations"<<endl;

    while(true){
        ring_buffer__poll(buffer_bpf,50);   //50 ms sleep
        continue;
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
                if(handleProgramInjection(message,fd) < 0){
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