#!/bin/sh

set -ex

# Setup. (ins kernel module, create device file at /dev/newdev)
insmod driver.ko
./mknoddev.sh newdev


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

## dd .... | strings 			-> PRINT AS STRING
## dd .... | od -An -t x1 		-> HEX DUMP

# printf '_do_fork\0' | dd bs=4 status=none of=/dev/newdev count=10 seek=4
# dd bs=4 status=none if=/dev/newdev count=1 skip=4 | od -Ad -c 
# dd bs=4 status=none if=/dev/newdev count=1 skip=1 | od -Ad -c

# printf '0' | dd bs=4 status=none of=/dev/newdev count=1 seek=0

# sleep 1 

# printf '0' | dd bs=4 status=none of=/dev/newdev count=1 seek=1




################### TEST INTERRUPT
printf "0001" | dd bs=4 status=none of=/dev/newdev count=1 seek=0


# printf "0001" | dd bs=4 status=none of=/dev/newdev count=1 seek=4
# dd bs=4 status=none if=/dev/newdev count=1 skip=4 | od -Ad -c 


#printf '0' | dd bs=4 status=none of=/dev/newdev count=1 seek=0
###############

# Teardown.
# rm /dev/newdev
# rmmod driver
