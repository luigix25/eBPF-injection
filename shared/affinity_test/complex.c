#define _GNU_SOURCE
#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdint.h>
#include <time.h>

#include <sched.h>
//affinity
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)
#define N_THREADS 4
#define BUFFER_SIZE 8*1024*1024
#define LOOP_TIMES 0xFFFF

pthread_t tid[N_THREADS];
pthread_mutex_t lock;
int target_cpu;
char* myregion;

void cpu_stress(void){
    volatile unsigned long long i;
    for (i = 0; i < 1000000000ULL; ++i);
}

int setaffinity_thread_self(int cpu){
    cpu_set_t* set;
    set = CPU_ALLOC(SET_SIZE);
    CPU_ZERO_S(SET_SIZE, set);
    CPU_SET_S(cpu, SET_SIZE, set);
    if(sched_setaffinity(gettid(), SET_SIZE, set) == -1){
        printf("Error in sched_setaffinity\n");
        CPU_FREE(set);
        return -1;
    }
    CPU_FREE(set);

    printf("This thread affinity on cpu 0\n");
    return 0;
}

int setaffinity_allno0_thread_self(){
    cpu_set_t* set;
    set = CPU_ALLOC(SET_SIZE);
    CPU_ZERO_S(SET_SIZE, set);
    CPU_SET_S(1, SET_SIZE, set);
    CPU_SET_S(2, SET_SIZE, set);
    CPU_SET_S(3, SET_SIZE, set);
    if(sched_setaffinity(gettid(), SET_SIZE, set) == -1){
        printf("Error in sched_setaffinity\n");
        CPU_FREE(set);
        return -1;
    }
    CPU_FREE(set);

    printf("This thread affinity on cpu 1 2 3\n");
    return 0;
}

void* doSomething(void *arg)
{
    unsigned long i = 0;   
    unsigned long index;
    char* myregion = (char*) arg;
    // printf("\n Job started\n");

    if(target_cpu >= 0){
        setaffinity_thread_self(target_cpu);
    }

    for(i=0; i<(LOOP_TIMES);i++){    
        if(i%50 == 0)    {
            sched_yield();
        }
        index = rand();
        while(index >= BUFFER_SIZE){
            index = rand();
        }
        *(myregion + index) += 1;
    }
    // printf("\n Job finished\n");
    return NULL;
}


int main(int argc, char *argv[])
{
    int i = 0;
    int err;
    cpu_set_t* set;
    srand(time(NULL));   // Initialization, should only be called once.

    if(argc != 2){
        printf("Usage: ./affinity_test <target_cpu>\ntarget_cpu <0 means no affinity.\ntarget_cpu >=0 means affinity with target_cpu\n");
        return -1;
    }

    target_cpu = atoi(argv[1]);

    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }

    myregion = malloc(BUFFER_SIZE);    //8 MiB alloc

    while(i < N_THREADS){
        if(i==0){
            err = pthread_create(&(tid[i]), NULL, &doSomething, myregion);
        }
        else{
            err = pthread_create(&(tid[i]), NULL, &doSomething, myregion);            
        }
        if (err != 0){
            printf("\ncan't create thread :[%s]", strerror(err));
        }
        i++;
    }

    for(i=0; i<N_THREADS; i++){
        pthread_join(tid[i], NULL);
    }

    pthread_mutex_destroy(&lock);



    return 0;
}