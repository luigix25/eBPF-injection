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

#define DYNAMIC_MEM_TYPE 2
#define MAX_ENTRIES 4096	//must be a power of two

typedef struct {
	uint64_t timeslot_start;
	uint64_t timeslot_duration;
	uint64_t global_threshold;
	uint64_t cpu;
	uint64_t counter;
} counter_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	counter_t data;
} container_t;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES);
} bpf_ringbuffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, counter_t);
} counters SEC(".maps");


/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful
*/

#define TIMESLOT_DURATION 100 	//ms
#define timeslot_alignment 100
#define threshold 0			//PER CPU
#define GLOBAL_THRESHOLD 3

int send_to_ringbuff(uint64_t cpu, uint64_t counter, uint64_t timeslot_start){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		bpf_printk("Error while reserving space on ringbuf\n");
		return -1;
	}

	container_obj->type = DYNAMIC_MEM_TYPE;
	container_obj->size = sizeof(counter_t);
	container_obj->data.cpu = cpu;
	container_obj->data.counter = counter;
	container_obj->data.timeslot_start = timeslot_start;
	container_obj->data.timeslot_duration = TIMESLOT_DURATION;
	container_obj->data.global_threshold = GLOBAL_THRESHOLD;

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

SEC("kprobe/balance_pgdat")
int bpf_prog1(struct pt_regs *ctx){
	
	uint32_t index = 0;
	counter_t *value = bpf_map_lookup_elem(&counters,&index);
	if(value == NULL){
		bpf_printk("NULL!\n");
		//can't happen!
		return -1;
	}

	bpf_printk("ciao %d\n",value->counter);	

	//bpf_printk("TS_START: %d",value->timeslot_start);

	//Helper that gets ts since boot
	uint64_t time = bpf_ktime_get_ns()/1000; //millisec
	//bpf_printk("Time: %d",time);

	uint64_t elapsed = time - value->timeslot_start;

	if(value->timeslot_start == 0 || elapsed >= TIMESLOT_DURATION){	//first execution or the timeslot is over
		//timeslot starts are all aligned to 100 ms: 100 200 etc
		value->timeslot_start = time - (time % timeslot_alignment);
		value->counter = 1;
		//return 0;
	}
	
	//Same timeslot, increasing counter

	//value->counter++;

	if(value->counter >= threshold){
		if(send_to_ringbuff(bpf_get_smp_processor_id(),value->counter,value->timeslot_start)){
			bpf_printk("FATAL ERROR: sending on the ringbuff\n");
			return -1;
		}
		value->counter = 0;
	}

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;		
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)
