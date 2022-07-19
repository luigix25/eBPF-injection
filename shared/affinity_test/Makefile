CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2
BUILD_DIR=build


all: affinity_test yield_affinity_test split_thread_test complex

affinity_test: affinity_test.c
	$(CC) $(CFLAGS) affinity_test.c -o ${BUILD_DIR}/affinity_test -lpthread

yield_affinity_test: yield_affinity_test.c
	$(CC) $(CFLAGS) yield_affinity_test.c -o ${BUILD_DIR}/yield_affinity_test -lpthread

split_thread_test: split_thread_test.c
	$(CC) $(CFLAGS) split_thread_test.c -o ${BUILD_DIR}/split_thread_test -lpthread

complex: complex.c
	$(CC) $(CFLAGS) complex.c -o ${BUILD_DIR}/complex -lpthread


clean:
	rm -f build/*