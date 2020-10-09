#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "You must enter exactly 1 command line argument (duration in seconds)"
    exit
fi

echo "Running for $1 seconds..."

timeout --signal=SIGINT $1 ./spscq 

echo "Timeout [SIGINT] after $1 seconds"
