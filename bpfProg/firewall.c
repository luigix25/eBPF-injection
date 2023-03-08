#include <stdint.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#include "header.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 4096	//must be a power of two
#define FIREWALL_TYPE 3

// Using BPF_MAP_TYPE_ARRAY map type all array elements pre-allocated 
// and zero initialized at init time

enum rule {DROP, ACCEPT, UNKNOWN = -1};

struct bpf_map_def SEC("maps") bpf_ringbuffer = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = MAX_ENTRIES,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct nft_chain);
} nft_chain_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct nft_table);
} nft_table_map SEC(".maps");

#define MAX_STRLEN 20

typedef struct{
	const char table_name[MAX_STRLEN];
	const char chain_name[MAX_STRLEN];
	uint32_t ip;
	uint32_t rule;
} firewall_info_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	firewall_info_t firewall_info_obj;
} container_t;

/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful
*/

static __always_inline int send_to_ringbuff(const char *chain_name, const char *table_name, uint32_t ip, uint32_t rule){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		bpf_printk("Error while reserving space on ringbuf\n");
		return -1;
	}

	container_obj->type = FIREWALL_TYPE;
	container_obj->size = sizeof(firewall_info_t);
	container_obj->firewall_info_obj.ip = ip;
	container_obj->firewall_info_obj.rule = rule;

	if(bpf_probe_read_str((void*)&container_obj->firewall_info_obj.table_name[0],MAX_STRLEN,table_name) < 0){
		bpf_printk("Error reading table name\n");
		bpf_ringbuf_discard(container_obj,0);
		return -1;
	}

	if(bpf_probe_read_str((void*)&container_obj->firewall_info_obj.chain_name[0],MAX_STRLEN,chain_name) < 0){
		bpf_printk("Error reading chain name\n");
		bpf_ringbuf_discard(container_obj,0);
		return -1;
	}

	bpf_printk("container %s %s\n",container_obj->firewall_info_obj.chain_name,container_obj->firewall_info_obj.table_name);

	bpf_ringbuf_submit(container_obj,0);

	return 0;

}

static __always_inline uint32_t read_nft_expr(struct nft_expr *nft_expr_ptr, uint32_t *ip, uint32_t *rule);


static __always_inline int analyze_nft_rule(struct nft_rule *nft_rule_ptr, uint32_t *ip, uint32_t *rule){

	struct nft_rule nft_rule_stack;
	bpf_probe_read(&nft_rule_stack, sizeof(struct nft_rule),nft_rule_ptr);

	void *expr_addr = nft_rule_ptr->data;

	uint32_t offset = 0;

	//Can't do unbounded loops
	for(int i=0;i<10;i++){
		//check if this expr is the latest
		if((void*)(nft_rule_ptr->data) + nft_rule_stack.dlen <= expr_addr )
			break;
		
		offset = read_nft_expr(expr_addr, ip, rule);
		expr_addr += offset;
	}

	return 0;

}


#define string_length 3 //arbitrary: need just 3 chars to determine expr type

//Returns expr length: they do not have a fixed size!
static __always_inline uint32_t read_nft_expr(struct nft_expr *nft_expr_ptr, uint32_t *ip, uint32_t *rule){

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

	//bpf_printk("Tipo: %s\n",nft_expr_type_stack.name);

	if(__builtin_memcmp(cmp_str,nome_ops,3) == 0){	//cmp
		struct nft_cmp_fast_expr  *payload_ptr = (struct nft_cmp_fast_expr *) nft_expr_ptr->data;
		struct nft_cmp_fast_expr payload_stack;
		bpf_probe_read(&payload_stack, sizeof(struct nft_cmp_fast_expr),payload_ptr);
		
		*ip = payload_stack.data;
		//IP here
		bpf_printk("IP %x\n",payload_stack.data);
	} else if(__builtin_memcmp(immediate_str,nome_ops,3) == 0){	//immediate
		struct nft_immediate_expr  *payload_ptr = (struct nft_immediate_expr *) nft_expr_ptr->data;
		struct nft_immediate_expr immediate_stack;
		//Can be optimized, from 24 bytes to 4
		bpf_probe_read(&immediate_stack, sizeof(struct nft_immediate_expr),payload_ptr);

		if(immediate_stack.data.verdict.code == 0){
			bpf_printk("DROP\n");
			*rule = DROP;
		} else if(immediate_stack.data.verdict.code == 1){
			bpf_printk("ACCEPT\n");
			*rule = ACCEPT;
		}

	}

	return return_value;
}



SEC("kprobe/nft_trans_rule_add") //(struct nft_ctx *ctx, int msg_type, struct nft_rule *rule)

int bpf_prog1(struct pt_regs *ctx){

	struct nft_ctx *nft_ctx_ptr;
	uint32_t ip, rule;
	/* Default */
	ip = -1;
	rule = UNKNOWN;

	nft_ctx_ptr = (struct nft_ctx *)PT_REGS_PARM1(ctx);

	analyze_nft_rule((struct nft_rule *)PT_REGS_PARM3(ctx), &ip, &rule);

	if(ip == -1 || rule == UNKNOWN){
		bpf_printk("Unknown rule!\n");
		return 0;
	}

	struct nft_ctx stack;
	bpf_probe_read(&stack,sizeof(struct nft_ctx),nft_ctx_ptr);

	uint32_t index = 0;

	//Table
	struct nft_table *nft_table_stack = bpf_map_lookup_elem(&nft_table_map,&index);
	if(nft_table_stack == NULL){
		return 0;
	}
	bpf_probe_read(nft_table_stack,sizeof(struct nft_table),stack.table);

	//Chain
	struct nft_chain *nft_chain_stack = bpf_map_lookup_elem(&nft_chain_map,&index);
	if(nft_chain_stack == NULL){
		return 0;
	}
	bpf_probe_read(nft_chain_stack,sizeof(struct nft_chain),stack.chain);

	send_to_ringbuff(nft_chain_stack->name,nft_table_stack->name, ip, rule);

    return 0;
}


char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)

