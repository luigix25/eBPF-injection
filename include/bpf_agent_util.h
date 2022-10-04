#define PIN 0
#define UNPIN 1

#define MAX_ENTRIES 64

#ifdef EBPF_PROG
    #define TYPE_SIZE u64
#else
    #define TYPE_SIZE uint64_t
#endif

typedef struct {
	TYPE_SIZE cpu_set;
	TYPE_SIZE op;
} cpu_set_op_t;
