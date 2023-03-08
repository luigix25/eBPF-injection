#!/usr/bin/python3
import sys

if(len(sys.argv) < 2):
    print ("Usage: ip")
    sys.exit(-1)

with open('xdp', 'rb') as f:
    s = f.read()
offset = s.find(b'\xaa\xbb\xcc\xdd') #placeholder for source

if(offset == -1):
    print ("magic number not found")
    sys.exit(-1)

#fileName = sys.argv[1]
ip = sys.argv[1]

ip_list = ip.split(".")
ip_list = list(map(int, ip_list)) #from list of str to list of int
byte_array = bytes(ip_list)

with open('xdp_patched', "wb") as fh:
    fh.write(s)
    fh.seek(offset)
    fh.write(byte_array)
