import statistics
import random
import os
import sys
import subprocess
import argparse
import time
from invoke import Responder
import fabric
from fabric import Connection, Config
import multiprocessing
from datetime import datetime, timedelta


intra_sleep_duration = 0.5
n_tests = 5


def prologue(vcpu_pinned, host_load, serial_percent, duration_each):
	start = datetime.now()
	print("RUNNING: " + sys.argv[0] +" Vcpu_pin=" + vcpu_pinned + " Load=" + host_load + " Serial=" + str(serial_percent) + "% Duration=" + str(duration_each))
	print("Launch time: " + start.strftime("%H:%M:%S"))
	# estimated_end = start + timedelta(seconds=n_tests*(duration_each + intra_sleep_duration))
	# print("Estimated termination: " + estimated_end.strftime("%H:%M:%S") + " ["+ str(n_tests*(duration_each +intra_sleep_duration)) +" seconds]")
	# print('')

def isBpfDaemonRunning(txt):
	for item in txt.split("\n"):
		if "daemon_bpf" in item:
			return 1
	return 0

def injectBpfProgram():
	#run ./injectProgram
	rc = subprocess.call("script/injectProgram.sh")
	# print("Bpf program injected")

def startCpuPinning():
	#place holder, you start pinning by running a program with sched_setaffinity in the guest
	print("start cpu pinning")

def resetCpuPinning():
	#run ./reset
	rc = subprocess.call("script/resetAffinity.sh")
	# print("CPU pinning reset")


def startHostLoad(load):
	# run ./unpinnedbusycpu.sh (spawn x yes command unpinned)	
	rc = subprocess.call(["script/unpinnedbusycpu.sh", str(load)])
	# print("Start host load: " + str(load))

def startHostLoadPinned(load):
	# run ./busycpu.sh (spawn 1*load yes command pinned for each cpu)
	for i in range(load):
		rc = subprocess.call("script/busycpu.sh")
	# print("Start host load (pinned): " + str(load))

def resetHostLoad():
	# run ./clearcpu.sh
	if host_load == 'no':
		pass
	else:
		rc = subprocess.call("script/clearcpu.sh")	
	# print("Reset host load")


def startAndStopSerialization(percentage, duration_each):	
	if percentage > 0:	
		# run ./pinonsame <percentage> <total duration of each test> 
		# (if percentage <=0 pinonsame prog do nothing and return)
		# run in background after a short delay, so it catchup with synchronous execution of the remote ssh test
		sleep_amount = getSleepAmount(percentage, duration_each)	
		os.system("(sleep " + str(sleep_amount) + "; ./script/pinOnSame.sh "+ str(percentage) +" " + str(duration_each) +")&")
	

def getSleepAmount(percentage, duration_each):
	min = duration_each * percentage/100 * 1.5  # cut a margin of percentage * 1.5
	max = duration_each - min
	return random.random() * (max - min) + min
	

def computeMeanAndStdDev(path):
	with open(path, "r") as filestream:
		for line in filestream:
			currentline = [float(numeric_string) for numeric_string in line.split(",")]
			print("Average Mpps: "+ str(statistics.mean(currentline)) +"\tStd. deviation: " + str(statistics.stdev(currentline)))	
	
	# with open(path, 'a') as fd:
	# 	fd.write(f'\n{str(statistics.mean(currentline))+","+ str(statistics.stdev(currentline))}')			

	print("------------------------------------")	



def cleanup():
	print("END time: ", datetime.now().strftime("%H:%M:%S"))
	resetHostLoad()
	resetCpuPinning()





# Parse arguments
parser = argparse.ArgumentParser(description='Test cpu affinity use case for extensible paravirtualization using eBPF.')
parser.add_argument('--v', metavar='vcpu', nargs=1, choices={'no', 'yes'},
					help='Whether or not pin guest vCPU to host pCPU [no, yes]')
parser.add_argument('--l', metavar='host_load', nargs=1,  choices={'no', 'low', 'high'},
					help='Whether or not load the host [no, low, high]')
parser.add_argument('--s', metavar='serial_percent', nargs=1, type=int,
					help='Which serialization percentage we require')
parser.add_argument('--d', metavar='duration', nargs=1, type=int,
					help='Duration of each test run in seconds')

args = parser.parse_args()

vcpu_pinned = args.v.pop()
host_load = args.l.pop()
serial_percent = args.s.pop()
duration_each = args.d.pop()
path = "results/" + "V" + vcpu_pinned + "_L" + host_load + "_S" + str(serial_percent) + "_D" + str(duration_each) + ".txt"

prologue(vcpu_pinned, host_load, serial_percent, duration_each)

sudo_pass = 'p'
config = Config(overrides={'sudo': {'password': sudo_pass}})
c = fabric.Connection(host='localhost', user='giacomo', port=2222, connect_kwargs={'password': 'p'}, config=config)	

# ----------------------- vCPU pinning support

if vcpu_pinned == 'no':
	# Check if bpf daemon is running on guest (should NOT run)
	r = c.run("ps -e", hide=True)
	if isBpfDaemonRunning(r.stdout):
		print("vcpu_pinned no")
		print("Error: Please make sure bpf daemon is OFF in the guest machine.")	
		exit(0)
elif vcpu_pinned == 'yes':
	# Check if bpf daemon is running on guest (should run)
	r = c.run("ps -e", hide=True)
	if not isBpfDaemonRunning(r.stdout):
		print("vcpu_pinned yes")
		print("Error: Please make sure bpf daemon is up and running in the guest machine.")		
		exit(0)
	else:
		# print("vcpu_pinned yes: Bpf daemon running in guest")
		pass

	# inject bpf kprobe on sched_setaffinity
	injectBpfProgram()	
	# Guest daemon apply bpf kprobe and it is now able to intercept sched_setaffinity syscalls

# ----------------------- HOST LOAD

if host_load == 'no':
	# no load, do nothing
	# print("host_load no")
	pass
elif host_load == 'low':
	# low is 2x yes per each core (unpinned!)	
	startHostLoad(multiprocessing.cpu_count()*2)
elif host_load == 'high':
	# high is 8x yes per each core (unpinned!)
	startHostLoad(multiprocessing.cpu_count()*8)

# ----------------------- SERIALIZATION PERCENTAGE
# print("Start serialization with "+ str(serial_percent) +"% of total time")

time.sleep(1)

# ----------------------- for loop TEST
f = open(path, "w")
for i in range(n_tests):
	startAndStopSerialization(serial_percent, duration_each)	
	with c.cd('shared/simplified-spscq'):
		r = c.run("python3 affinity_test.py " + str(duration_each), hide=True)
		f.write(r.stdout)		
		if i != n_tests-1:
			f.write(',')			

	time.sleep(intra_sleep_duration)

f.close()



c.close()
cleanup()

computeMeanAndStdDev(path)
