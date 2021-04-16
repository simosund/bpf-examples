/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define MAX_TCP_OPTIONS 10

#define INCLUDE_TCP_TS_PARSING //undefine to skip parsing the TCP options
#define INCLUDE_IPV6SUPPORT    //undefine to remove IPv6 code path
#define INCLUDE_SOUREDEST_SWAP //undefine to remove the logic that swaps source and dest for ingress

char _license[] SEC("license") = "GPL";

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

/* Longest chain of IPv6 extension headers to resolve */
#ifndef IPV6_EXT_MAX_CHAIN
#define IPV6_EXT_MAX_CHAIN 6
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

struct flow_address {
	struct in6_addr ip;
	__u16 port;
	__u16 reserved;
};

/*
 * Struct to hold a full network tuple
 */
struct network_tuple {
	struct flow_address saddr;
	struct flow_address daddr;
	__u16 proto; //IPPROTO_TCP, IPPROTO_ICMP etc.
	__u8 ipv; //AF_INET or AF_INET6
	__u8 reserved;
};


struct packet_id {
	struct network_tuple flow;
	__u32 identifier; //tsval for TCP packets
};

/*
 * This struct keeps track of the data and data_end pointers from the xdp_md or
 * __skb_buff contexts, as well as a currently parsed to position kept in nh.
 * Additionally, it also keeps the length of the entire packet, which together
 * with the other members can be used to determine ex. how much data each
 * header encloses.
 */
struct parsing_context {
	void *data; //Start of eth hdr
	void *data_end; //End of safe acessible area
	struct hdr_cursor nh; //Position to parse next
	__u32 pkt_len; //Full packet length (headers+data)
	bool is_egress; //Is packet on egress or ingress?
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

#ifdef INCLUDE_IPV6SUPPORT
static __always_inline int skip_ip6hdrext(struct hdr_cursor *nh,
					  void *data_end,
					  __u8 next_hdr_type)
{
	for (int i = 0; i < IPV6_EXT_MAX_CHAIN; ++i) {
		struct ipv6_opt_hdr *hdr = nh->pos;

		if (hdr + 1 > data_end)
			return -1;

		switch (next_hdr_type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_MH:
			nh->pos = (char *)hdr + (hdr->hdrlen + 1) * 8;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_AH:
			nh->pos = (char *)hdr + (hdr->hdrlen + 2) * 4;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_FRAGMENT:
			nh->pos = (char *)hdr + 8;
			next_hdr_type = hdr->nexthdr;
			break;
		default:
			/* Found a header that is not an IPv6 extension header */
			return next_hdr_type;
		}
	}

	return -1;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return skip_ip6hdrext(nh, data_end, ip6h->nexthdr);
}
#endif

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}

#ifdef INCLUDE_TCP_TS_PARSING
static int parse_tcp_ts(struct tcphdr *tcph, void *data_end, __u32 *tsval,
			__u32 *tsecr)
{
	int len = tcph->doff << 2;
	void *opt_end = (void *)tcph + len;
	__u8 *pos = (__u8 *)(tcph + 1); //Current pos in TCP options
	__u8 i, opt;
	volatile __u8 opt_size; // Seems to ensure it's always read of from stack as u8

	if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
		return -1;
#pragma unroll //temporary solution until we can identify why the non-unrolled loop gets stuck in an infinite loop
	for (i = 0; i < MAX_TCP_OPTIONS; i++) {
		if (pos + 1 > opt_end || pos + 1 > data_end)
			return -1;

		opt = *pos;
		if (opt == 0) // Reached end of TCP options
			return -1;

		if (opt == 1) { // TCP NOP option - advance one byte
			pos++;
			continue;
		}

		// Option > 1, should have option size
		if (pos + 2 > opt_end || pos + 2 > data_end)
			return -1;
		opt_size = *(pos + 1);
		if (opt_size < 2) // Stop parsing options if opt_size has an invalid value
			return -1;

		// Option-kind is TCP timestap (yey!)
		if (opt == 8 && opt_size == 10) {
			if (pos + 10 > opt_end || pos + 10 > data_end)
				return -1;
			*tsval = *(__u32 *)(pos + 2);
			*tsecr = *(__u32 *)(pos + 6);
			return 0;
		}

		// Some other TCP option - advance option-length bytes
		pos += opt_size;
	}
	return -1;
}
#endif

static int parse_tcp_identifier(struct parsing_context *ctx, __be16 *sport,
				__be16 *dport, __u32 *identifier)
{
	__u32 tsval = 1, tsecr = 2;
	struct tcphdr *tcph;

	if (parse_tcphdr(&ctx->nh, ctx->data_end, &tcph) < 0)
		return -1;
#ifdef INCLUDE_TCP_TS_PARSING
	if (parse_tcp_ts(tcph, ctx->data_end, &tsval, &tsecr) < 0)
		return -1;
#endif
	*sport = tcph->source;
	*dport = tcph->dest;
	*identifier = ctx->is_egress ? tsval : tsecr;
	return 0;
}

static int parse_packet_identifier(struct parsing_context *ctx,
				   struct packet_id *p_id)
{
	int proto, err;
	struct ethhdr *eth;
	struct iphdr *iph;
#ifdef INCLUDE_IPV6SUPPORT
	struct ipv6hdr *ip6h;
#endif
	struct flow_address *saddr, *daddr;

#ifdef INCLUDE_SOUREDEST_SWAP
	// Switch saddr <--> daddr on ingress to match egress
	if (ctx->is_egress) {
		saddr = &p_id->flow.saddr;
		daddr = &p_id->flow.daddr;
	} else {
		saddr = &p_id->flow.daddr;
		daddr = &p_id->flow.saddr;
	}
#else
	saddr = &p_id->flow.saddr;
	daddr = &p_id->flow.daddr;
#endif

	proto = parse_ethhdr(&ctx->nh, ctx->data_end, &eth);

	// Parse IPv4/6 header
	if (proto == bpf_htons(ETH_P_IP)) {
		p_id->flow.ipv = AF_INET;
		proto = parse_iphdr(&ctx->nh, ctx->data_end, &iph);
	}
#ifdef INCLUDE_IPV6SUPPORT
	else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_id->flow.ipv = AF_INET6;
		proto = parse_ip6hdr(&ctx->nh, ctx->data_end, &ip6h);
	}
#endif
	else {
		return -1;
	}

	// Add new protocols here
	if (proto == IPPROTO_TCP) {
		err = parse_tcp_identifier(ctx, &saddr->port, &daddr->port,
					   &p_id->identifier);
		if (err)
			return -1;
	} else {
		return -1;
	}

	return 0;
}

// Programs

// XDP program for parsing identifier in ingress traffic and check for match in map
SEC("xdp")
int pping_ingress(struct xdp_md *ctx)
{
	struct packet_id p_id = { 0 };
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = pctx.data_end - pctx.data,
		.nh = { .pos = pctx.data },
		.is_egress = false,
	};

	if (parse_packet_identifier(&pctx, &p_id) < 0)
		goto out;

	bpf_printk("XDP - TSecr: %u\n", p_id.identifier);
out:
	return XDP_PASS;
}


// TC-BFP for parsing packet identifier from egress traffic and add to map
SEC("classifier")
int pping_egress(struct __sk_buff *skb)
{
	struct packet_id p_id = { 0 };
	struct parsing_context pctx = {
		.data = (void *)(long)skb->data,
		.data_end = (void *)(long)skb->data_end,
		.pkt_len = skb->len,
		.nh = { .pos = pctx.data },
		.is_egress = true,
	};

	if (parse_packet_identifier(&pctx, &p_id) < 0)
		goto out;

	bpf_printk("tc - TSval: %u\n", p_id.identifier);
out:
	return BPF_OK;
}
