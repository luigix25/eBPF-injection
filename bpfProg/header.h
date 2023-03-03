//#include <stdint.h>
#include <stdbool.h>

struct nft_ctx {
	uint64_t *            		net;                 /*     0     8 */
	struct nft_table *         table;                /*     8     8 */
	struct nft_chain *         chain;                /*    16     8 */
	void * nla;              					     /*    24     8 */
	uint32_t                        portid;               /*    32     4 */
	uint32_t                        seq;                  /*    36     4 */
	uint16_t                        flags;                /*    40     2 */
	uint8_t                         family;               /*    42     1 */
	uint8_t                         level;                /*    43     1 */
	uint8_t 	                       report;               /*    44     1 */

	/* size: 48, cachelines: 1, members: 10 */
	/* padding: 3 */
	/* last cacheline: 48 bytes */
};

struct nft_table {
	uint64_t            		list[2];             /*     0    16 */
	uint64_t		            chains_ht[17];       /*    16   136 */
	/* --- cacheline 2 boundary (128 bytes) was 24 bytes ago --- */
	uint64_t           			chains[2];               /*   152    16 */
	uint64_t		            sets[2];                 /*   168    16 */
	uint64_t           		    objects[2];              /*   184    16 */
	/* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
	uint64_t           			flowtables[2];           /*   200    16 */
	uint64_t                        hgenerator;           /*   216     8 */
	uint64_t                        handle;               /*   224     8 */
	uint32_t                        use;                  /*   232     4 */
	uint16_t                        family:6;             /*   236: 0  2 */
	uint16_t                        flags:8;              /*   236: 6  2 */
	uint16_t                        genmask:2;            /*   236:14  2 */

	/* XXX 2 bytes hole, try to pack */

	uint32_t                        nlpid;                /*   240     4 */

	/* XXX 4 bytes hole, try to pack */

	char *                     name;                 /*   248     8 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	uint16_t                        udlen;                /*   256     2 */

	/* XXX 6 bytes hole, try to pack */

	uint8_t *                       udata;                /*   264     8 */

	/* size: 272, cachelines: 5, members: 16 */
	/* sum members: 258, holes: 3, sum holes: 12 */
	/* sum bitfield members: 16 bits (2 bytes) */
	/* last cacheline: 16 bytes */
};

struct nft_chain {
	struct nft_rule * *        rules_gen_0;          /*     0     8 */
	struct nft_rule * *        rules_gen_1;          /*     8     8 */
	uint64_t           		   rules[2];                /*    16    16 */
	uint64_t		           list[2];                 /*    32    16 */
	uint64_t        		   rhlhead[2];              /*    48    16 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct nft_table *         table;                /*    64     8 */
	uint64_t                        handle;               /*    72     8 */
	uint32_t                        use;                  /*    80     4 */
	uint8_t                         flags:5;              /*    84: 0  1 */
	uint8_t                         bound:1;              /*    84: 5  1 */
	uint8_t                         genmask:2;            /*    84: 6  1 */

	/* XXX 3 bytes hole, try to pack */

	char *                     name;                 /*    88     8 */
	uint16_t                        udlen;                /*    96     2 */

	/* XXX 6 bytes hole, try to pack */

	uint8_t *                       udata;                /*   104     8 */
	struct nft_rule * *        rules_next;           /*   112     8 */

	/* size: 120, cachelines: 2, members: 15 */
	/* sum members: 110, holes: 2, sum holes: 9 */
	/* sum bitfield members: 8 bits (1 bytes) */
	/* last cacheline: 56 bytes */
};

struct nft_rule {
	uint64_t           		   list[2];                 /*     0    16 */
	uint64_t                        handle:42;            /*    16: 0  8 */
	uint64_t                        genmask:2;            /*    16:42  8 */
	uint64_t                        dlen:12;              /*    16:44  8 */
	uint64_t                        udata:1;              /*    16:56  8 */

	/* XXX 7 bits hole, try to pack */

	unsigned char              data[] __attribute__((__aligned__(8))); /*    24     0 */
//	uint64_t              data __attribute__((__aligned__(8))); /*    24     0 */

	/* size: 24, cachelines: 1, members: 6 */
	/* sum members: 16 */
	/* sum bitfield members: 57 bits, bit holes: 1, sum bit holes: 7 bits */
	/* forced alignments: 1 */
	/* last cacheline: 24 bytes */
} __attribute__((__aligned__(8)));

struct nft_expr {
	const struct nft_expr_ops	*ops;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(uint64_t))));
};

struct nft_expr_ops {
	uint64_t				a;
	uint64_t				b;
	unsigned int		size;

	uint64_t				c;
	uint64_t				d;
	uint64_t				e;
	uint64_t				f;
	uint64_t				g;
	uint64_t				h;
	uint64_t				i;
	uint64_t				j;
	uint64_t				k;
	uint64_t				l;
	uint64_t				m;
	const struct nft_expr_type	*type;
	void				*data;
};

struct nft_expr_type {
	uint64_t a;
	uint64_t b;
	const struct nft_expr_ops	*ops;
	uint64_t		list[2];
	const char				*name;
	struct module			*owner;
	const struct nla_policy		*policy;
	unsigned int			maxattr;
	uint8_t				family;
	uint8_t				flags;
};


enum nft_payload_bases {
	NFT_PAYLOAD_LL_HEADER,
	NFT_PAYLOAD_NETWORK_HEADER,
	NFT_PAYLOAD_TRANSPORT_HEADER,
	NFT_PAYLOAD_INNER_HEADER,
};


struct nft_payload {
	enum nft_payload_bases	base:8;
	uint8_t			offset;
	uint8_t			len;
	uint8_t			dreg;
};

enum nft_cmp_ops {
	NFT_CMP_EQ,
	NFT_CMP_NEQ,
	NFT_CMP_LT,
	NFT_CMP_LTE,
	NFT_CMP_GT,
	NFT_CMP_GTE,
};

struct nft_verdict {
	uint32_t				code;
	struct nft_chain		*chain;
};

struct nft_data {
	union {
		uint32_t			data[4];
		struct nft_verdict	verdict;
	};
} __attribute__((aligned(__alignof__(uint64_t))));

struct nft_cmp_expr {
	struct nft_data		data;
	uint8_t			sreg;
	uint8_t			len;
	enum nft_cmp_ops	op:8;
};

struct nft_cmp_fast_expr {
	uint32_t			data;
	uint32_t			mask;
	uint8_t			sreg;
	uint8_t			len;
	bool			inv;
};

struct nft_immediate_expr {
	struct nft_data		data;
	uint8_t			dreg;
	uint8_t			dlen;
};
