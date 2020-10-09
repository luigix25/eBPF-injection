import argparse
import time
import statistics
from datetime import datetime, timedelta
import subprocess

# Parse arguments
parser = argparse.ArgumentParser(description='Execute spscq tests.')
parser.add_argument('duration', metavar='d', type=int, nargs=1, default=30,
                   help='duration in seconds of each test')
args = parser.parse_args()

	# Echo process passes password to the sudo timeout ./spscq
echo_process = subprocess.Popen(["echo", "p"], stdout=subprocess.PIPE)
subprocess.call(["sudo", "-S", "timeout", "--signal=SIGINT", str(args.duration[0]), "./spscq"], stdin=echo_process.stdout)
