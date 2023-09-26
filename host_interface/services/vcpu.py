import socket
import struct
import os
import sys
import asyncio
from qemu.qmp import QMPClient
import ebpf_service

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 9999  # The port used by the server

PROTOCOL_VERSION = bytes([1])

class bpf_injection_result:
    STRUCT_FORMAT = '=qq'
    size = struct.calcsize(STRUCT_FORMAT)

    def __init__(self, bytes): # costruttore
        data = struct.unpack(bpf_injection_result.STRUCT_FORMAT,bytes)
        self.cpu_mask = data[0]
        self.operation = data[1]

    def __str__(self):
        return f"Cpu mask: {self.cpu_mask} Operation: {self.operation}"

'''
    uint64_t cpu_mask;
    uint64_t operation;	//0 pin 1 unpin
'''


'''
?: boolean
c: char
h: short
l: long
i: int
f: float
q: long long int
= packed

struct bpf_injection_msg_header {
	uint8_t version;		//version of the protocol
	uint8_t type;			//what kind of payload is carried
	uint8_t service;		//VCPU_PINNING_TYPE, DYNAMIC_MEM_TYPE[..]
	uint16_t payload_len;	//payload length
} __attribute__((__packed__));

'''

def prova(param):
    return {"pid": param["thread-id"],"count":0}

async def main(argv):
    try:
        file_size = os.path.getsize(argv[1])
        print(f"File Size in Bytes is {file_size}")
    except FileNotFoundError:
        print("File not found.")
        return

    qmp = QMPClient('qemu')
    await qmp.connect('/tmp/qmp-sock')

    res = await qmp.execute('query-cpus-fast')

    #Pid for each cpu
    cpu = list(map(prova,res))
    await qmp.disconnect()

    header_obj = ebpf_service.bpf_injection_msg_header(PROTOCOL_VERSION,ebpf_service.PROGRAM_INJECTION,ebpf_service.VCPU_TYPE,file_size)

    header = header_obj.pack()
    print(header_obj)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, open(argv[1], "rb") as f:
        s.connect((HOST, PORT))
        s.sendall(header)

        bytes_read = f.read(file_size)
        s.sendall(bytes_read)

        print("Program Injected")

        if ebpf_service.initial_handshake(s) < 0:
            print("Injection not ok")
            sys.exit(-1)

        print("Injection Ok")


        while True:
            data =  ebpf_service.get_result(s)
            if data == -1:
                sys.exit(-1)

            result_obj = bpf_injection_result(data)
            handle_data_result(result_obj,cpu)

def trailing_zeros(number):
    n_bits = 8

    formatted_string = format(number, f'0{n_bits}b')

    index = 0
    for char in reversed(formatted_string):
        if char == '0':
            index += 1
        else:
            break

    return index

def handle_data_result(result_obj,cpu):

    index = trailing_zeros(result_obj.cpu_mask)

    if result_obj.operation != 0: #unpin
        cpu[index]["count"] -= 1
        if cpu[index]["count"] == 0:
            print("Unpinning")
            os.sched_setaffinity(cpu[index]["pid"],set(range(0,len(cpu))))
            res = os.sched_getaffinity(cpu[index]["pid"])
            print("Affinity after unpinning",res)
    else:
        cpu[index]["count"] += 1
        if cpu[index]["count"] == 1:
            print("Pinning")
            os.sched_setaffinity(cpu[index]["pid"],{index})
            res = os.sched_getaffinity(cpu[index]["pid"])
            print("Affinity after pinning",res)

if __name__ == "__main__":
    if(len(sys.argv) < 3):
        print("Usage [file to inject] [qmp-socket]")
    asyncio.run(main(sys.argv))