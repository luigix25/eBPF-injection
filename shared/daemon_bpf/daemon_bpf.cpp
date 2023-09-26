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
#include "ServiceList.h"

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
	if (len < (int32_t)sizeof(bpf_injection_msg_header)) {
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

    uint32_t data_len = sizeof(bpf_injection_msg_header) + event->size;

    bpf_injection_msg_header *hdr = (bpf_injection_msg_header*)malloc(data_len);
    hdr->payload_len = event->size;
    hdr->service = event->type;
    hdr->type = PROGRAM_INJECTION_RESULT;
    hdr->version = 1;

    memcpy((char*)hdr+sizeof(*hdr),&event->payload,hdr->payload_len);

    //For debug
    //uint64_t *ptr = (uint64_t*)&event->payload;

    int dev_fd = reinterpret_cast<long>(ctx);

    if(write(dev_fd,hdr,data_len) == -1){ //Type and Payload
        cout<<"Can't write to the device\n";
        free(hdr);
        return -1;
    }

    free(hdr);
    return 0;

}

void sendAck(int dev_fd,uint8_t service, bool success){

    //header + payload (1 byte)
    uint16_t buf_length = sizeof(bpf_injection_msg_header) + sizeof(bpf_injection_ack);
    uint8_t *buffer = (uint8_t*) malloc(buf_length);

    bpf_injection_msg_header *message = reinterpret_cast<bpf_injection_msg_header*>(buffer);
    message->type = PROGRAM_INJECTION_ACK;
    message->version = DEFAULT_VERSION;
    message->payload_len = sizeof(bpf_injection_ack);
    message->service = service;

    bpf_injection_ack *payload = reinterpret_cast<bpf_injection_ack *>(buffer+sizeof(bpf_injection_msg_header));
    payload->status = (success) ? INJECTION_OK : INJECTION_FAIL;

    int8_t res = write(dev_fd,buffer,buf_length);
    if(res <= 0){
        cout<<"Error while sending ACK"<<endl;
    }

    printf("Ack sent!\n");
    free(buffer);

}

int handleProgramInjection(int dev_fd, bpf_injection_msg_t message){

    BpfLoader loader(message);
    int map_fd = loader.loadAndGetMap();
    if(map_fd < 0){
        cout<<"Map Not Found"<<endl;
        return -1;
    }

    ring_buffer *buffer_bpf = ring_buffer__new(map_fd,handler_ringbuf,(void*)(long)dev_fd,NULL);
    cout<<"[LOG] Starting operations"<<endl;

    sendAck(dev_fd,message.header.service,true);

    while(true){
        ring_buffer__poll(buffer_bpf,50);   //50 ms sleep
        continue;
    }
}

/*This function will kill the service, if found */
void kill_service(ServiceList &list, const bpf_injection_msg_t &message){

    Service s = list.findService(message.header.service);

    if(s.service_id != (uint8_t)-1){
        cout<<"Unloading Service n: "<<(int)s.service_id<<"\n";
        kill(s.pid,SIGKILL);
        list.removeService(s);
    }

}

int main(){

    cout<<"[LOG] Starting Guest Agent"<<endl;

    int fd = open("/dev/virtio-ports/org.fedoraproject.port.0",O_RDWR);
    if(fd < 0){
        cout<<"Error while opening device"<<endl;
        return -1;
    }

    ServiceList list;

    while(true){

        bpf_injection_msg_t message = recv_bpf_injection_msg(fd);

        if(message.header.type == PROGRAM_INJECTION){

            kill_service(list, message); //Kill running service, if any
            pid_t pid = fork();

            if(pid == 0){ //child
                if(handleProgramInjection(fd,message) < 0){
                    cerr<<"Generic Error"<<endl;
                    sendAck(fd,message.header.service,false); //nack to the service
                    return -1;
                }

            } else { //parent

                Service s(message.header.service,pid);
                list.addService(s);

                continue;
            }

        } else if(message.header.type == PROGRAM_INJECTION_UNLOAD){
            kill_service(list, message);
        } else {
            cout<<"Unrecognized Payload Type: 0x"<<hex<<message.header.type<<"\n";
        }

    }


    //cleanup
    close(fd);

	return 0;

}
