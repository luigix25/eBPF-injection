

all: affinity_test.c yield_affinity_test.c split_thread_test.c complex.c
	gcc affinity_test.c -o affinity_test -lpthread
	gcc yield_affinity_test.c -o yield_affinity_test -lpthread
	gcc split_thread_test.c -o split_thread_test -lpthread
	gcc complex.c -o complex -lpthread

clean:
	rm -f affinity_test