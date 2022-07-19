CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2
BUILD_DIR=build


all: ${BUILD_DIR}/affinity_test ${BUILD_DIR}/yield_affinity_test ${BUILD_DIR}/split_thread_test ${BUILD_DIR}/complex

${BUILD_DIR}/affinity_test: affinity_test.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread

${BUILD_DIR}/yield_affinity_test: yield_affinity_test.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread

${BUILD_DIR}/split_thread_test: split_thread_test.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread

${BUILD_DIR}/complex: complex.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread


clean:
	rm -f build/*