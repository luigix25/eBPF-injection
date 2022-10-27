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

#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>

#include <asm/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DYNAMIC_MEM_TYPE 2

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
#define MAX_ENTRIES 4096	//must be a power of two

// Using BPF_MAP_TYPE_ARRAY map type all array elements pre-allocated 
// and zero initialized at init time

struct bpf_map_def SEC("maps") bpf_ringbuffer = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") pids = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = MAX_ENTRIES,
};


typedef struct {
	u64 type;
	u64 size;
	#warning aggiungere campo qui
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

int send_to_ringbuff(u64 cpu_set, u64 operation){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		bpf_printk("Error while reserving space on ringbuf\n");
		return -1;
	}

	container_obj->type = DYNAMIC_MEM_TYPE;
	container_obj->size = 3;//sizeof(cpu_mask_t);
	//container_obj->cpu_mask_obj.cpu_mask = cpu_set;
	//container_obj->cpu_mask_obj.operation = operation;

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

static u64 last_ts = 0;

SEC("kprobe/__swap_writepage")
int bpf_prog1(struct pt_regs *ctx){
	
	
	//Helper that gets ts since boot
	u64 time = bpf_ktime_get_ns();

	u64 elapsed = time - last_ts;
	//considerare quando last_ts è a 0
	bpf_printk("Elapsed %d\n",elapsed);

	last_ts = time;



	/*
	if(send_to_ringbuff()){
		bpf_printk("Error while sending on the ringbuff\n");
		return -1;
	}*/

	//bpf_map_update_elem(&pids, &pid, &cpu_set, BPF_ANY);	
	//bpf_printk("Pinned: PID %d\n",pid);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;		
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)
