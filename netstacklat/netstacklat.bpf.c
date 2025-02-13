/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Constants set by userspace
volatile const signed long long TAI_OFFSET = (37LL * NS_PER_S);
volatile const unsigned long long HISTCONFIG_BIN_LIMITS[HIST_MAX_BINS] = { 0 };
volatile const unsigned long HISTCONFIG_NBINS = HIST_MAX_BINS;

/* Helpers in maps.bpf.h require any histogram key to be a struct with a bucket member */
struct hist_key {
	u32 bucket;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_MAX_BINS + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_v4_do_rcv_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_MAX_BINS + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_data_queue_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_MAX_BINS + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_queue_rcv_seconds SEC(".maps");

/*
 * Find the correct histogram bin index for val.
 * Uses a binary search to search through all of the bin limits in
 * HISTCONFIG_BIN_LIMITS and select the appropirate one. Creates a
 * right-inclusive histogram, i.e. it will return index i for
 * HISTCONFIG_BIN_LIMITS[i - 1] < val <= HISTCONFIG_BIN_LIMITS[i]. Values outside
 * the histogram range will be placed in the first or last bin.
 */
static u32 search_histbin_idx(u64 val)
{
	u32 low = 0, high = HISTCONFIG_NBINS - 1;
	u32 mid;

	if (val <= HISTCONFIG_BIN_LIMITS[low])
		return low;
	if (val >= HISTCONFIG_BIN_LIMITS[high])
		return high;

	while (low < high - 1) {
		mid = (low + high) / 2;

		if (val == HISTCONFIG_BIN_LIMITS[mid])
			return mid;
		if (val > HISTCONFIG_BIN_LIMITS[mid])
			low = mid;
		else
			high = mid;
	}

	return high;
}

static void increment_histogram_nosync(void *map, struct hist_key key,
				       u64 value)
{
	u64 *bin_count;

	// Increment histogram
	key.bucket = search_histbin_idx(value);
	bin_count = bpf_map_lookup_elem(map, &key);
	if (bin_count)
		(*bin_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = HISTCONFIG_NBINS;
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

	increment_histogram_nosync(hook_to_histmap(hook), key, delta_ns);
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
