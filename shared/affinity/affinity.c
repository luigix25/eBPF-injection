#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)

int
main(int argc, char *argv[]){
    cpu_set_t* set;    
    int i;
    int pid;
    int cpu_target;
    struct timespec tim;
    uint64_t val;
    tim.tv_sec = 0;
    tim.tv_nsec = 50000000L;    //50ms

    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cpu to set affinity with>\n", argv[0]);
        return -1;
    }

    cpu_target = atoi(argv[1]);
    

    set = CPU_ALLOC(MAX_CPU);    
    CPU_ZERO_S(SET_SIZE, set);
    CPU_SET_S(cpu_target, SET_SIZE, set);
    printf("This cpuset size:%ld\n", SET_SIZE);

    for(i=0; i<MAX_CPU; i++){
        if(CPU_ISSET_S(i, SET_SIZE, set)){
            printf("cpu %d is set\n", i);
        }
    }
    memcpy(&val, set, SET_SIZE);
    printf("Mycpuset value is %lu\n", val);
    pid = getpid();
    printf("Calling sched_setaffinity(pid=%d, size=%ld, ..)\n", pid, SET_SIZE);
    if (sched_setaffinity(pid, SET_SIZE, set) == -1){
        printf("error setaffinity\n");
        return -1;
    }
    printf("sched_setaffinity called.\n");
        
    for(i=0; i<2; i++){
        nanosleep(&tim, NULL);
        // if(i%5==0)
        //     printf("sleep %i\n", i);
    }

}