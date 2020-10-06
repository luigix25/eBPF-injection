#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "You must enter exactly 1 command line argument (how many YES program you want to launch)"
    exit
fi

loop=$1
i=0

for (( i=0; i<loop; i++ ))
do
   yes > /dev/null &
done

# echo "yes [$1x]command running"
