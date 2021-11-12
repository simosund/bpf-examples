/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h> // Help functions that can be called from BPF programs, see man bpf-helpers
//#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
//#include <linux/tcp.h>
//#include <linux/icmp.h>
//#include <linux/icmpv6.h>
#include <stdbool.h>

#include <xdp/parsing_helpers.h> // Red Hat have made a bunch of help-function for parsing commong headers
#include "udptime.h"

char _license[] SEC("license") = "GPL"; // Necessary to use many of the bpf_helpers

// Global config struct - set from userspace
static volatile const struct bpf_config config = {};

// Map definitions
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// XDP program for parsing packet and retrieving timestamp from packet
SEC("xdp")
int pping_xdp_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct udp_timestamp udp_ts = { .arrival_time = bpf_ktime_get_ns() };

	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	int proto;

	proto = parse_ethhdr(&nh, data_end, &eth);

	if (proto == bpf_htons(ETH_P_IP)) { // IPv4
		proto = parse_iphdr(&nh, data_end, &iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) { // IPv6
		proto = parse_ip6hdr(&nh, data_end, &ip6h);
	} else {
		return XDP_PASS;
	}

	if (proto != IPPROTO_UDP) // Not UDP packet or failed parsing IP-header
		return XDP_PASS;

	if (parse_udphdr(&nh, data_end, &udph) < 0) // Failed parsing UDP packet
		return XDP_PASS;

	if (udph->dest != config.dport) // Wrong UDP dest port
		return XDP_PASS;

	if (nh.pos + sizeof(__u64) > data_end) // Packet not big enough
		return XDP_PASS;

	udp_ts.packet_timestamp = *(__u64 *)(nh.pos); // Read first 8 bytes from packet
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &udp_ts,
			      sizeof(udp_ts));

	return XDP_PASS;
}
