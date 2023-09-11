/*
 * BPF program to monitor CPU affinity tuning
 * 2020 - 2022 Luigi Leonardi and Giacomo Pellicci
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
#include <sys/types.h>

#define VCPU_PINNING_TYPE 1

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
#define MAX_ENTRIES 4096	//must be a power of two
#define PIN 0
#define UNPIN 1

// Using BPF_MAP_TYPE_ARRAY map type all array elements pre-allocated
// and zero initialized at init time

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES);
} bpf_ringbuffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, uint32_t);
	__type(value, uint32_t);
} pids SEC(".maps");

typedef struct{
	uint64_t cpu_mask;
	uint64_t operation;	//0 pin 1 unpin
} cpu_mask_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	cpu_mask_t cpu_mask_obj;
} container_t;

/*	System call prototype:
		asmlinkage long sys_sched_setaffinity(pid_t pid, unsigned int len,
					unsigned long __user *user_mask_ptr);

	In-kernel function sched_setaffinity has the following prototype:
		sched_setaffinity(pid_t pid, const struct cpumask *new_mask);

	This is what we kprobe, not the system call.
*/


/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful
*/

int send_to_ringbuff(uint64_t cpu_set, uint64_t operation){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		bpf_printk("Error while reserving space on ringbuf\n");
		return -1;
	}

	container_obj->type = VCPU_PINNING_TYPE;
	container_obj->size = sizeof(cpu_mask_t);
	container_obj->cpu_mask_obj.cpu_mask = cpu_set;
	container_obj->cpu_mask_obj.operation = operation;

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

SEC("kprobe/sched_setaffinity")
int bpf_prog1(struct pt_regs *ctx){
	uint32_t pid;
	uint64_t cpu_set;

	//If pid == 0, means current process
	pid = (pid_t)PT_REGS_PARM1(ctx);
	if(pid == 0){
		pid = bpf_get_current_pid_tgid() >> 32;
	}

	// Read from onst struct cpumask *new_mask (2nd parameter)
	if(bpf_probe_read(&cpu_set, 8, (void*)PT_REGS_PARM2(ctx)))
		return 0;

	uint64_t operation = PIN;

	if(cpu_set == (uint64_t)-1){ //unpinning
		bpf_map_delete_elem(&pids,&pid);
		operation = UNPIN;
	}

	if(send_to_ringbuff(cpu_set,operation)){
		bpf_printk("Error while sending on the ringbuff\n");
		return -1;
	}

	bpf_map_update_elem(&pids, &pid, &cpu_set, BPF_ANY);
	bpf_printk("Pinned: PID %d\n",pid);

    return 0;
}


SEC("kprobe/do_exit")
int probe_do_exit(struct pt_regs *ctx){
	uint32_t pid = bpf_get_current_pid_tgid() >> 32;
	uint32_t *elem;

	elem = (uint32_t*)bpf_map_lookup_elem(&pids,&pid);
	if(!elem){
		return 0;
	}

	if(send_to_ringbuff((uint64_t)(*elem),UNPIN)){
		bpf_printk("Error while sending on the ringbuff\n");
		return -1;
	}

	bpf_printk("DO exit: PID %d\n",pid);
	bpf_map_delete_elem(&pids,&pid);


	return 0;
}


char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)
