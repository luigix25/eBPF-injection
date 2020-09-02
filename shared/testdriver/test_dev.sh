#!/bin/sh

set -ex

# Setup. (ins kernel module, create device file at /dev/newdev)
insmod driver.ko
./mknoddev.sh testnewdev


 # *	+----+------------------------------+
 # *	|  0 |     	REGISTER_KPROBE 		|
 # *	+----+------------------------------+
 # *	|  4 |     	UNREGISTER_KPROBE  		|
 # *	+----+------------------------------+
 # *	|  8 | LOAD KPROBE_TARGET FROM HOST |
 # *	+----+------------------------------+
 # *	| 12 |               ---          	|
 # *	+----+------------------------------+
 # *	| 16 |  	KPROBE_TARGET[0] 		|
 # *	+----+------------------------------+
 # *	| 20 |   	KPROBE_TARGET[1]  		|
 # *	+----+------------------------------+
 # *	| 24 |   	KPROBE_TARGET[2]  		|
 # *	+----+------------------------------+
 # *	| 28 |   	KPROBE_TARGET[3]  		|
 # *	+----+------------------------------+


################### TEST INTERRUPT
printf '11' | dd bs=4 status=none of=/dev/testnewdev count=1 seek=2


# dd bs=4 status=none if=/dev/testnewdev count=1 skip=0 | od -Ad -c 


#printf '0' | dd bs=4 status=none of=/dev/newdev count=1 seek=0
###############




# sleep 1
# ls
# sleep 1
# UNREGISTER_KPROBE
# printf '0' | dd bs=4 status=none of=/dev/newdev count=1 seek=1

# Teardown.
rm /dev/testnewdev
rmmod driver
