#define _GNU_SOURCE
#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdint.h>

#include <sched.h>
#include <time.h> 
//affinity
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)

#define N_THREADS   8
pthread_t tid[N_THREADS];
uint64_t counter = 0;
int split_load; //0=no 1=yes
char* zone0;
char* zone1;
char* zone2;
char* zone3;
char* zone4;
char* zone5;
char* zone6;
char* zone7;

void* doSomeThing(void *arg){
    unsigned long i = 0;  
    unsigned long j = 0;          
    cpu_set_t* set;
    clock_t t; 
    double time_taken;
    char* zone = (char*)arg;
    int cpu_bound = *zone;
    
    if(split_load == 1){           
        set = CPU_ALLOC(SET_SIZE);
        CPU_ZERO_S(SET_SIZE, set);
        if(*zone == 0){
            CPU_SET_S(*zone, SET_SIZE, set);
            printf("Thread setaffinity to cpu#%d\n", *zone);
        }
        else{            
            CPU_SET_S(1, SET_SIZE, set);
            CPU_SET_S(2, SET_SIZE, set);
            CPU_SET_S(3, SET_SIZE, set);
            printf("Thread#%d setaffinity to cpu#1,2,3\n", *zone);
        }
        if(pthread_setaffinity_np(pthread_self(), SET_SIZE, set) == -1){
            printf("Error in sched_setaffinity\n");
            CPU_FREE(set);
            return NULL;
        }    

        pthread_getaffinity_np(pthread_self(), SET_SIZE, set);
        memcpy(&counter, set, SET_SIZE);
        CPU_FREE(set);
    }

    printf("\n Job started\n");
    t = clock(); 

    // (0xFFFFFFFF)
    for(i=0; i<(0xFF);i++){   
        for(j=0; j<(1024*1024); j++){
            *(zone + j) += 1;
        }
    }

    t = clock() - t; 
    time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
  
    if(cpu_bound == 0){
        printf("Job(bound to cpu#%d) took %f seconds to execute \n", cpu_bound, time_taken); 
    }
    else if(cpu_bound == 1){
        printf("Job(bound to cpu#1,2,3) took %f seconds to execute \n", time_taken);    
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    int i = 0;
    int err;
    cpu_set_t* set;

    //1mb zones
    zone0 = malloc(1024*1024);
    memset(zone0, 0, 1024*1024);
    *zone0 = 0;
    zone1 = malloc(1024*1024);
    memset(zone1, 0, 1024*1024);
    memset(zone1, 1, 1);
    zone2 = malloc(1024*1024);
    memset(zone2, 0, 1024*1024);
    memset(zone2, 1, 1);
    zone3 = malloc(1024*1024);
    memset(zone3, 0, 1024*1024);
    memset(zone3, 1, 1);
    zone4 = malloc(1024*1024);
    memset(zone4, 0, 1024*1024);
    memset(zone4, 1, 1);
    zone5 = malloc(1024*1024);
    memset(zone5, 0, 1024*1024);
    memset(zone5, 1, 1);
    zone6 = malloc(1024*1024);
    memset(zone6, 0, 1024*1024);
    memset(zone6, 1, 1);
    zone7 = malloc(1024*1024);
    memset(zone7, 0, 1024*1024);
    memset(zone7, 1, 1);

    
    if(argc != 2){
        printf("Usage: ./%s <split_load>\nsplit_load=0 means no split\nsplit_load=1 means split\n", argv[0]);
        return -1;
    }
    split_load = atoi(argv[1]);
    if(split_load == 0){
        printf("No split_load.\n");
    }
    else if(split_load == 1){
        printf("split_load activated.\n");
    }

    err = pthread_create(&(tid[0]), NULL, &doSomeThing, zone0);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
    
    err = pthread_create(&(tid[1]), NULL, &doSomeThing, zone1);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));

    err = pthread_create(&(tid[2]), NULL, &doSomeThing, zone2);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
    
    err = pthread_create(&(tid[3]), NULL, &doSomeThing, zone3);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));

    err = pthread_create(&(tid[4]), NULL, &doSomeThing, zone4);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
    
    err = pthread_create(&(tid[5]), NULL, &doSomeThing, zone5);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));

    err = pthread_create(&(tid[6]), NULL, &doSomeThing, zone6);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
    
    err = pthread_create(&(tid[7]), NULL, &doSomeThing, zone7);
    if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));


    for(i=0; i<N_THREADS; i++){
        pthread_join(tid[i], NULL);
    }

    free(zone0);
    free(zone1);
    free(zone2);
    free(zone3);
    free(zone4);
    free(zone5);
    free(zone6);
    free(zone7);
    return 0;
}