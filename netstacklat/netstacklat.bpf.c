/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "GPL";

volatile const signed long long TAI_OFFSET = (37LL * NS_PER_S);

/* Helpers in maps.bpf.h require any histogram key to be a struct with a bucket member */
struct hist_key {
	u32 bucket;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_ip_start_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_conntrack_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_start_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_start_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_sock_queue_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_sock_queue_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_sock_read_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_sock_read_seconds SEC(".maps");

static u32 get_exp2_histogram_bin_idx(u64 value, u32 max_bin)
{
	u32 bin = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bin > 0 && 1ULL << bin < value)
		bin++;

	if (bin > max_bin)
		bin = max_bin;

	return bin;
}

static void increment_exp2_histogram_nosync(void *map, struct hist_key key,
					    u64 value, u32 max_bin)
{
	u64 *bin_count;

	// Increment histogram
	key.bucket = get_exp2_histogram_bin_idx(value, max_bin);
	bin_count = bpf_map_lookup_elem(map, &key);
	if (bin_count)
		(*bin_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = max_bin + 1;
	bin_count = bpf_map_lookup_elem(map, &key);
	if (bin_count)
		*bin_count += value;
}

static void *hook_to_histmap(enum netstacklat_hook hook)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		return &netstack_latency_ip_start_seconds;
	case NETSTACKLAT_HOOK_CONNTRACK:
		return &netstack_latency_conntrack_seconds;
	case NETSTACKLAT_HOOK_TCP_START:
		return &netstack_latency_tcp_start_seconds;
	case NETSTACKLAT_HOOK_UDP_START:
		return &netstack_latency_udp_start_seconds;
	case NETSTACKLAT_HOOK_TCP_SOCK_QUEUE:
		return &netstack_latency_tcp_sock_queue_seconds;
	case NETSTACKLAT_HOOK_UDP_SOCK_QUEUE:
		return &netstack_latency_udp_sock_queue_seconds;
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		return &netstack_latency_tcp_sock_read_seconds;
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		return &netstack_latency_udp_sock_read_seconds;
	default:
		return NULL;
	}
}

static ktime_t time_since(ktime_t tstamp)
{
	ktime_t now;

	if (tstamp <= 0)
		return -1;

	now = bpf_ktime_get_tai_ns() - TAI_OFFSET;
	if (tstamp > now)
		return -1;

	return now - tstamp;
}

static void record_latency(ktime_t latency, enum netstacklat_hook hook)
{
	struct hist_key key = { 0 };
	increment_exp2_histogram_nosync(hook_to_histmap(hook), key, latency,
					HIST_MAX_LATENCY_SLOT);
}

static void record_latency_since(ktime_t tstamp, enum netstacklat_hook hook)
{
	ktime_t latency = time_since(tstamp);
	if (latency >= 0)
		record_latency(latency, hook);
}

SEC("fentry/ip_rcv_core")
int BPF_PROG(netstacklat_ip_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/ip6_rcv_core")
int BPF_PROG(netstacklat_ip6_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fexit/ipv4_conntrack_in")
int BPF_PROG(netstacklat_ipv4_conntrack_in, void *priv, struct sk_buff *skb,
	     void *state)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_CONNTRACK);
	return 0;
}

SEC("fexit/ipv6_conntrack_in")
int BPF_PROG(netstacklat_ipv6_conntrack_in, void *priv, struct sk_buff *skb,
	     void *state)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_CONNTRACK);
	return 0;
}

SEC("fentry/tcp_v4_rcv")
int BPF_PROG(netstacklat_tcp_v4_rcv, struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/tcp_v6_rcv")
int BPF_PROG(netstacklat_tcp_v6_rcv, struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/udp_rcv")
int BPF_PROG(netstacklat_udp_rcv, struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fentry/udpv6_rcv")
int BPF_PROG(netstacklat_udpv6_rcv, struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fexit/tcp_data_queue")
int BPF_PROG(netstacklat_tcp_data_queue, struct sock *sk, struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_TCP_SOCK_QUEUE);
	return 0;
}

SEC("fexit/udp_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udp_queue_rcv_one_skb, struct sock *sk,
	     struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_UDP_SOCK_QUEUE);
	return 0;
}

SEC("fexit/udpv6_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udpv6_queue_rcv_one_skb, struct sock *sk,
	     struct sk_buff *skb)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_UDP_SOCK_QUEUE);
	return 0;
}

SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	struct timespec64 *ts = &tss->ts[0];
	record_latency_since((ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			     NETSTACKLAT_HOOK_TCP_SOCK_READ);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_latency_since(skb->tstamp, NETSTACKLAT_HOOK_UDP_SOCK_READ);
	return 0;
}
