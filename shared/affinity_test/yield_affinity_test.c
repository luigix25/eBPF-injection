#define _GNU_SOURCE
#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdint.h>

#include <sched.h>
//affinity
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)

#define N_THREADS   64
pthread_t tid[N_THREADS];
uint64_t counter = 0;
pthread_mutex_t lock;

void* doSomeThing(void *arg)
{
    unsigned long i = 0;   
    // printf("\n Job started\n");

    // (0xFFFFFFFF)
    for(i=0; i<(0xFFFF);i++){        
        __sync_fetch_and_add(&counter, 1);                
    }

    // printf("\n Job finished\n");
    return NULL;
}

int main(int argc, char *argv[])
{
    int i = 0;
    int err;
    cpu_set_t* set;
    int target_cpu;
    
    if(argc != 2){
        printf("Usage: ./affinity_test <target_cpu>\ntarget_cpu <0 means no affinity.\ntarget_cpu >=0 means affinity with target_cpu\n");
        return -1;
    }
    target_cpu = atoi(argv[1]);
    printf("Target cpu for affinity is: %d\n", target_cpu);
    if(target_cpu >= 0){
        set = CPU_ALLOC(SET_SIZE);
        CPU_ZERO_S(SET_SIZE, set);
        CPU_SET_S(target_cpu, SET_SIZE, set);
        if(sched_setaffinity(gettid(), SET_SIZE, set) == -1){
            printf("Error in sched_setaffinity\n");
            CPU_FREE(set);
            return -1;
        }
        CPU_FREE(set);
    }

    // sched_getaffinity(0, sizeof(set), &set);
    // memcpy(&counter, &set, sizeof(set));
    // printf("%lx\n", counter);

    while(i < N_THREADS)
    {
        err = pthread_create(&(tid[i]), NULL, &doSomeThing, NULL);
        if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
        i++;
    }

    for(i=0; i<N_THREADS; i++){
        pthread_join(tid[i], NULL);
    }

    return 0;
}