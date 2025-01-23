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
} netstack_latency_tcp_v4_do_rcv_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_data_queue_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_queue_rcv_seconds SEC(".maps");

static u32 get_exp2_histogram_bin_idx(u64 value, u32 max_bin)
{
	u32 bin = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bin > 0 && 1 << bin < value)
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
	case NETSTACKLAT_HOOK_TCP_V4_DO_RCV:
		return &netstack_latency_tcp_v4_do_rcv_seconds;
	case NETSTACKLAT_HOOK_TCP_DATA_QUEUE:
		return &netstack_latency_tcp_data_queue_seconds;
	case NETSTACKLAT_HOOK_UDP_QUEUE_RCV_ONE:
		return &netstack_latency_udp_queue_rcv_seconds;
	default:
		return NULL;
	}
}

static void record_current_netstacklat(struct sk_buff *skb,
				       enum netstacklat_hook hook)
{
	ktime_t delta_ns, skb_tstamp;
	struct hist_key key = { 0 };

	if (!skb)
		return;

	skb_tstamp = BPF_CORE_READ(skb, tstamp);
	if (skb_tstamp == 0)
		return;

	delta_ns = bpf_ktime_get_tai_ns() - TAI_OFFSET - skb_tstamp;
	if (delta_ns < 0)
		return;

	increment_exp2_histogram_nosync(hook_to_histmap(hook), key, delta_ns,
					HIST_MAX_LATENCY_SLOT);
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(netstacklat_tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_TCP_V4_DO_RCV);
	return 0;
}

SEC("fentry/tcp_data_queue")
int BPF_PROG(netstacklat_tcp_data_queue, struct sock *sk, struct sk_buff *skb)
{
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_TCP_DATA_QUEUE);
	return 0;
}

SEC("fentry/udp_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udp_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_UDP_QUEUE_RCV_ONE);
	return 0;
}
