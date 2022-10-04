/*
 * BPF program to monitor CPU affinity tuning
 * 2020 Giacomo Pellicci
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

#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>

#include <asm/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
#define MAX_ENTRIES 64


// Using BPF_MAP_TYPE_ARRAY map type all array elements pre-allocated 
// and zero initialized at init time
#define PIN 0
#define UNPIN 1

typedef struct {
	u64 cpu_set;
	u64 op;
} cpu_set_op_t;

struct bpf_map_def SEC("maps") values_index = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") values = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(cpu_set_op_t),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") pids = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

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

static s32 insert_value(cpu_set_op_t *value){

	u32 *top;
	u32 index = 0;

	top = bpf_map_lookup_elem(&values_index, &index);	
	if (!top){ //entry not found! should never reach here!
		return -1;
	}

	if(*top == MAX_ENTRIES){ //map is full
		return -1;
	}

	__sync_fetch_and_add(top, 1);
	index = *top;

	return !bpf_map_update_elem(&values, &index, value, BPF_ANY);

}

SEC("kprobe/sched_setaffinity")
int bpf_prog1(struct pt_regs *ctx){
	u32 pid;
	u64 cpu_set;

	//If pid == 0, means current process
	pid = (pid_t)PT_REGS_PARM1(ctx);
	if(pid == 0){
		pid = bpf_get_current_pid_tgid() >> 32;
	}

	// Read from struct cpumask *new_mask (2nd parameter)
	if(bpf_probe_read(&cpu_set, 8, (void*)PT_REGS_PARM2(ctx))){
		bpf_printk("Error reading cpu_mask from ctx\n");
		return -1;
	}

	cpu_set_op_t value;
	value.op = PIN;
	value.cpu_set = cpu_set;

	if(!insert_value(&value)){
		bpf_printk("Error in insert value\n");
		return -1;
	}

	//Registering PID for tracking in exit
	bpf_map_update_elem(&pids, &pid, &cpu_set, BPF_ANY);	
	bpf_printk("Pinned: PID %d\n",pid);

    return 0;    
}


SEC("kprobe/do_exit")
int probe_do_exit(struct pt_regs *ctx){

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *elem;

	elem = bpf_map_lookup_elem(&pids,&pid);
	if(!elem){
		return 0;
	} 

	cpu_set_op_t value;
	value.op = UNPIN;
	value.cpu_set = *elem;

	if(!insert_value(&value))
		return -1;

	bpf_printk("DO exit: PID %d\n",pid);
	bpf_map_delete_elem(&pids,&pid);
		
	return 0;
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;		
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)
