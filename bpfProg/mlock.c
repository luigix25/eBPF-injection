/*
 * BPF program to monitor Memory Swaps
 * 2022 Luigi Leonardi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>

#include <asm/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <stdint.h>

#define MAX_ENTRIES 4096	//must be a power of two
#define MLOCK_TYPE 4
#define LOCK 1
#define UNLOCK 2

/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example
 **/

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES);
} bpf_ringbuffer SEC(".maps");

struct bpf_iter_memory {
	__u64 __opaque[4];
} __attribute__((aligned(8)));

typedef struct{
	uint64_t op;
	void *addr;
} mlock_info_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	mlock_info_t mlock_info_obj;
} container_t;

extern int bpf_iter_memory_new(struct bpf_iter_memory *it, unsigned int pid, unsigned long long vaddr) __weak __ksym;
extern uint64_t* bpf_iter_memory_next(struct bpf_iter_memory *it) __weak __ksym;
extern void bpf_iter_memory_destroy(struct bpf_iter_memory *it) __weak __ksym;

int send_to_ringbuff(void *addr, uint64_t op){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		bpf_printk("Error while reserving space on ringbuf\n");
		return -1;
	}

	container_obj->type = MLOCK_TYPE;
	container_obj->size = sizeof(mlock_info_t);
	container_obj->mlock_info_obj.op = op;
	container_obj->mlock_info_obj.addr = addr;

	bpf_printk("container op %d %px\n",container_obj->mlock_info_obj.op,container_obj->mlock_info_obj.addr);

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

uint64_t virt_to_phys(uint64_t pid, uint64_t vaddr){

	struct bpf_iter_memory it;
	uint64_t *v;
	uint64_t i;

	bpf_iter_memory_new(&it, pid, (unsigned long long)vaddr);

	bpf_printk("address: %lx Pid %d\n",vaddr,pid);

	for(i=0;i<4;i++){
		v = bpf_iter_memory_next(&it);
		if(!v)
			goto error;
		bpf_printk("Liv %d Ptr = %lx , value = %llx",4-i,v, *v);

	}

	error:
		bpf_iter_memory_destroy(&it);
		return -1;

	return *v;
}

//int do_mlock(unsigned long start, size_t len, vm_flags_t flags)
SEC("kprobe/do_mlock")
int bpf_prog1(struct pt_regs *ctx){

	bpf_printk("ciao\n");

	uint64_t pid = bpf_get_current_pid_tgid();
	pid &= 0xFFFFFFFF;

	uint64_t addr = (uint64_t)PT_REGS_PARM1(ctx);
	uint32_t length = (uint32_t)PT_REGS_PARM2(ctx);

	uint32_t i;
	uint32_t n_pages = length/4096;

	if(n_pages > 4000)
		n_pages = 4000;

	for(i=0;i<n_pages;i++){

		uint64_t paddr = virt_to_phys(pid,addr + i*4096);
	
		if(send_to_ringbuff((void*)paddr,LOCK) != 0){
			bpf_printk("errore send buffer\n");
		}

	}

	return 0;

}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)

