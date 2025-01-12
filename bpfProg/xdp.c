#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
//#include <linux/ipv6.h>
#include <linux/udp.h>

#include <stdint.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

SEC("prog")
int xdp_drop_benchmark_traffic(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	uint64_t nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		return XDP_PASS;
	}

	uint16_t h_proto = eth->h_proto;
	int i;

	/* Handle double VLAN tagged packet. See https://en.wikipedia.org/wiki/IEEE_802.1ad */
	for (i = 0; i < 2; i++) {
		if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
			struct vlan_hdr *vhdr;

			vhdr = data + nh_off;
			nh_off += sizeof(struct vlan_hdr);
			if (data + nh_off > data_end) {
				return XDP_PASS;
			}
			h_proto = vhdr->h_vlan_encapsulated_proto;
		}
	}

	if (h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		struct udphdr *udph = data + nh_off + sizeof(struct iphdr);
		if (udph + 1 > (struct udphdr *)data_end) {
			return XDP_PASS;
		}
		/*if (iph->protocol == IPPROTO_UDP &&
		    (htonl(iph->daddr) & 0xFFFFFF00) ==  0xC6120000 // 198.18.0.0/24
		    && udph->dest == htons(1234)) {
			return XDP_DROP;
		}*/
        if (htonl(iph->daddr) ==  0xC0A80302){ // 192.168.3.2
			    return XDP_DROP;
		    }

    }

	return XDP_PASS;
}

