#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#include "header.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

typedef struct{
	u64 cpu_mask;
	u64 operation;	//0 pin 1 unpin
} cpu_mask_t;

typedef struct {
	u64 type;
	u64 size;
	cpu_mask_t cpu_mask_obj;
} container_t;

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

	container_obj->type = 0;
	container_obj->size = sizeof(cpu_mask_t);
	container_obj->cpu_mask_obj.cpu_mask = cpu_set;
	container_obj->cpu_mask_obj.operation = operation;

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

static __always_inline uint32_t read_nft_expr(struct nft_expr *nft_expr_ptr);


static __always_inline int funzione(struct nft_rule *nft_rule_ptr){

	struct nft_rule nft_rule_stack;
	bpf_probe_read(&nft_rule_stack, sizeof(struct nft_rule),nft_rule_ptr);

	void *expr_addr = nft_rule_ptr->data;

	uint32_t offset = 0;

	//Can't do unbounded loops
	for(int i=0;i<10;i++){
		//check if this expr is the latest
		if((void*)(nft_rule_ptr->data) + nft_rule_stack.dlen <= expr_addr )
			break;
		
		offset = read_nft_expr(expr_addr);
		expr_addr += offset;
	}

	return 0;

}


#define string_length 3 //arbitrary: need just 3 chars to determine expr type

//Returns expr length: they do not have a fixed size!
static __always_inline uint32_t read_nft_expr(struct nft_expr *nft_expr_ptr){

	uint32_t return_value = 0;

	struct nft_expr nft_expr_stack;
	bpf_probe_read(&nft_expr_stack,sizeof(struct nft_expr),nft_expr_ptr); 
	
	//Expr ops
	struct nft_expr_ops nft_expr_ops_stack;
	bpf_probe_read(&nft_expr_ops_stack,sizeof(struct nft_expr_ops),nft_expr_stack.ops);


	return_value = nft_expr_ops_stack.size;
	//bpf_printk("expr ops size %d\n",nft_expr_ops_stack.size); //0 impossibile!!

	//Expr ops type
	struct nft_expr_type nft_expr_type_stack;
	bpf_probe_read(&nft_expr_type_stack,sizeof(struct nft_expr_type),nft_expr_ops_stack.type);


	const char *cmp_str = "cmp";
	const char *immediate_str = "imm"; //immediate

	char nome_ops[string_length];
	bpf_probe_read(&nome_ops[0],string_length,nft_expr_type_stack.name); //need to read chars from memory

	bpf_printk("Tipo: %s\n",nft_expr_type_stack.name);

	if(__builtin_memcmp(cmp_str,nome_ops,3) == 0){	//cmp
		struct nft_cmp_fast_expr  *payload_ptr = (struct nft_cmp_fast_expr *) nft_expr_ptr->data;
		struct nft_cmp_fast_expr payload_stack;
		bpf_probe_read(&payload_stack, sizeof(struct nft_cmp_fast_expr),payload_ptr);
		
		//IP here
		bpf_printk("IP %x\n",payload_stack.data);
	} else if(__builtin_memcmp(immediate_str,nome_ops,3) == 0){	//immediate
		struct nft_immediate_expr  *payload_ptr = (struct nft_immediate_expr *) nft_expr_ptr->data;
		struct nft_immediate_expr immediate_stack;
		//Can be optimized, from 24 bytes to 4
		bpf_probe_read(&immediate_stack, sizeof(struct nft_immediate_expr),payload_ptr);

		if(immediate_stack.data.verdict.code == 0){
			bpf_printk("DROP\n");
		} else if(immediate_stack.data.verdict.code == 1){
			bpf_printk("ACCEPT\n");
		}

		bpf_printk("%x\n",immediate_stack.data.verdict.code);
	}

	return return_value;
}



SEC("kprobe/nft_trans_rule_add") //(struct nft_ctx *ctx, int msg_type, struct nft_rule *rule)

int prog(struct pt_regs *ctx){

	struct nft_ctx *nft_ctx_ptr;

	nft_ctx_ptr = (struct nft_ctx *)PT_REGS_PARM1(ctx);

	funzione((struct nft_rule *)PT_REGS_PARM3(ctx));

	struct nft_ctx stack;
	bpf_probe_read(&stack,sizeof(struct nft_ctx),nft_ctx_ptr);


	//Table
	struct nft_table stack_2;
	bpf_probe_read(&stack_2,sizeof(struct nft_table),stack.table);

	//Chain
	struct nft_chain stack_3;
	bpf_probe_read(&stack_3,sizeof(struct nft_chain),stack.chain);

	bpf_printk("table: %s, chain: %s\n",stack_2.name,stack_3.name);

    return 0;
}

/*
SEC("kprobe/nft_expr_dump")
int prog_old(struct pt_regs *ctx){
	//bpf_printk("nft_expr_dump\n");
	read_nft_expr((struct nft_expr *)PT_REGS_PARM3(ctx));
	return 0;
}
*/
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)

