import os
import sys
import argparse
import time
from datetime import datetime, timedelta

def header():
	print("\n###################################################################")
	print("\tExtensible paravirtualization using eBPF")
	print("\tMaster's Thesis, Giacomo Pellicci, Universita di Pisa")
	print("###################################################################\n")
	start = datetime.now()
	print("Test launch time: " + start.strftime("%H:%M:%S") + '\n')

if __name__ == "__main__":
	# Parse arguments
	parser = argparse.ArgumentParser(description='Test cpu affinity use case for extensible paravirtualization using eBPF.')

	parser.add_argument('--d', metavar='duration', nargs='?', type=int, default=60,
						help='Duration of each test run in seconds (default 60)')
	parser.add_argument('--v', metavar='vcpu_pinned', nargs='?', default='no', choices={'no', 'yes'},
						help='Whether or not pin guest vCPU to host pCPU [no, yes] (default no)')

	args = parser.parse_args()
	duration = args.d	
	vcpu_pinned = args.v

	header()

	if vcpu_pinned == 'no':
		#VCPU NOT PINNED	
		os.system("python3 test.py --v no --l no --s 0 --d " + str(duration))		#no load
		time.sleep(1)
		os.system("python3 test.py --v no --l low --s 0 --d " + str(duration))		#low load
		time.sleep(1)
		os.system("python3 test.py --v no --l high --s 0 --d " + str(duration))		#high load no serial
		time.sleep(1)
		os.system("python3 test.py --v no --l high --s 2 --d " + str(duration))		#high load serial 2%
		time.sleep(1)
		os.system("python3 test.py --v no --l high --s 10 --d " + str(duration))	#high load serial 10%
		time.sleep(1)
		os.system("python3 test.py --v no --l high --s 20 --d " + str(duration))	#high load serial 20%
		time.sleep(1)


	else:		
		#VCPU PINNED
		# FROM NOW ON ***ONLY*** YOU NEED DAEMON_BPF RUNNING ON GUEST
		os.system("python3 test.py --v yes --l no --s 0 --d " + str(duration))		#no load
		time.sleep(1)
		os.system("python3 test.py --v yes --l low --s 0 --d " + str(duration))		#low load
		time.sleep(1)
		os.system("python3 test.py --v yes --l high --s 0 --d " + str(duration))	#high load no serial
		time.sleep(1)

		#Serialization is impossible with vcpu pinning!