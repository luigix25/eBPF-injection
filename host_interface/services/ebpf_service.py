import struct

PROGRAM_INJECTION = bytes([1])
PROGRAM_INJECTION_ACK = bytes([2])
PROGRAM_INJECTION_RESULT = bytes([3])
PROGRAM_INJECTION_UNLOAD = bytes([4])

VCPU_TYPE = bytes([1])
MEMORY_TYPE = bytes([2])
FIREWALL_TYPE = bytes([3])

class bpf_injection_msg_header:
    STRUCT_FORMAT = '=ccch'
    size = struct.calcsize(STRUCT_FORMAT)

    def __init__(self, protocol, type, service, size): # costruttore
        self.version = protocol
        self.type = type
        self.service = service
        self.payload_size = size

    def from_bytes(bytes): # costruttore
        data = struct.unpack(bpf_injection_msg_header.STRUCT_FORMAT,bytes)
        return bpf_injection_msg_header(data[0],data[1],data[2],data[3])

    def pack(self):
        return struct.pack(bpf_injection_msg_header.STRUCT_FORMAT,self.version,self.type,self.service,self.payload_size)

    def __str__(self):
        return f"Version: {self.version} Type: {self.type} Service: {self.service} Size: {self.payload_size}"

class bpf_injection_ack:
    STRUCT_FORMAT = '=c'
    INJECTION_OK = bytes([0])
    INJECTION_FAIL = bytes([1])

    size = struct.calcsize(STRUCT_FORMAT)

    def __init__(self, bytes): # costruttore
        data = struct.unpack(bpf_injection_ack.STRUCT_FORMAT,bytes)
        self.status = data[0]

    def __str__(self):
        return f"Status: {self.status}"

def initial_handshake(s):
    #waiting for ack
    data = s.recv(bpf_injection_msg_header.size)
    header = bpf_injection_msg_header.from_bytes(data)

    print(header)
    if(header.type != PROGRAM_INJECTION_ACK):
        print("Protocol error")
        return -1

    data = s.recv(bpf_injection_ack.size)
    status_obj = bpf_injection_ack(data)

    if(status_obj.status == bpf_injection_ack.INJECTION_OK):
        return 0
    else:
        return -1

def get_result(s):
    data = s.recv(bpf_injection_msg_header.size)
    header = bpf_injection_msg_header.from_bytes(data)

    if header.type != PROGRAM_INJECTION_RESULT:
        print("Protocol error")
        return -1

    return s.recv(header.payload_size)
