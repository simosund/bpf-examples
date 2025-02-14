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
} netstack_latency_netif_receive_skb_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcf_classify_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_nf_conntrack_in_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_ipt_do_table_seconds SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_tcp_recvmsg_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_latency_udp_recvmsg_seconds SEC(".maps");

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
	case NETSTACKLAT_HOOK_NETIF_RECEIVE_SKB:
		return &netstack_latency_netif_receive_skb_seconds;
	case NETSTACKLAT_HOOK_TCF_CLASSIFY:
		return &netstack_latency_tcf_classify_seconds;
	case NETSTACKLAT_HOOK_NF_CONNTRACK_IN:
		return &netstack_latency_nf_conntrack_in_seconds;
	case NETSTACKLAT_HOOK_IPT_DO_TABLE:
		return &netstack_latency_ipt_do_table_seconds;
	case NETSTACKLAT_HOOK_TCP_V4_DO_RCV:
		return &netstack_latency_tcp_v4_do_rcv_seconds;
	case NETSTACKLAT_HOOK_TCP_DATA_QUEUE:
		return &netstack_latency_tcp_data_queue_seconds;
	case NETSTACKLAT_HOOK_UDP_QUEUE_RCV_ONE:
		return &netstack_latency_udp_queue_rcv_seconds;
	case NETSTACKLAT_HOOK_TCP_RECVMSG:
		return &netstack_latency_tcp_recvmsg_seconds;
	case NETSTACKLAT_HOOK_UDP_RECVMSG:
		return &netstack_latency_udp_recvmsg_seconds;
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
	//skb_tstamp = skb->tstamp; // Use this by default, BPF_CORE_READ() only for non-fentry hooks
	if (skb_tstamp == 0)
		return;

	delta_ns = bpf_ktime_get_tai_ns() - TAI_OFFSET - skb_tstamp;
	if (delta_ns < 0)
		return;

	increment_exp2_histogram_nosync(hook_to_histmap(hook), key, delta_ns,
					HIST_MAX_LATENCY_SLOT);
}

// Use the netif_receive_skb raw tracepoint over fentry, should be lower overhead and more stable
// Furthermore, the netif_receive_skb() function does not appear to trigger as reliably
SEC("raw_tracepoint/netif_receive_skb")
int BPF_PROG(netstacklat_netif_receive_skb, struct sk_buff *skb, int len, char name[])
{
	// TODO - figure out why we get some "latencies" that are like 1k seconds..., somehow underflow?
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_NETIF_RECEIVE_SKB);
	return 0;
}

/* SEC("fentry/netif_receive_skb") */
/* int BPF_PROG(netstacklat_netif_receive_skb, struct sk_buff *skb) */
/* { */
/* 	record_current_netstacklat(skb, NETSTACKLAT_HOOK_NETIF_RECEIVE_SKB); */
/* 	return 0; */
/* } */

SEC("fentry/tcf_classify")
int BPF_PROG(netstacklat_tcf_classify, struct sk_buff *skb,
	     void *block, void *tp,
	     void *res, bool compat_mode)
{
	// TODO: This one doesn't seem to trigger, find corresponding TC hook
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_TCF_CLASSIFY);
	return 0;
}

SEC("fentry/nf_conntrack_in")
int BPF_PROG(netstacklat_nf_conntrack_in, struct sk_buff *skb, void *state)
{
	// TODO: Filter for ingress? Figure out super high latencies...
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_NF_CONNTRACK_IN);
	return 0;
}

SEC("fentry/ipt_do_table")
int BPF_PROG(netstacklat_ipt_do_table, void *priv, struct sk_buff *skb,
	     void *state)
{
	// TODO: This one doesn't seem to trigger, figure out why or find replacement
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_IPT_DO_TABLE);
	return 0;
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(netstacklat_tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb)
{
	// TODO: Drop this one?
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

SEC("fentry/udpv6_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udpv6_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_UDP_QUEUE_RCV_ONE);
	return 0;
}

/*
 * How to get time packet is actually read from socket?
 * The tcp_recvmsg() and udp_recvmsg()/udpv6_recvmsg() functions seem like they
 * would correspond well, however they only have a sock and not an sk_buff as a
 * parameter, so how to get the timestamp?
 *
 * Could potentially use the sock->sk_stamp, however that doesn't appear to be
 * set most of the time (probably only set if the RX stamp was requested by the
 * socket).
 *
 * The sock_recv_timestamp(), __sock_recv_timestamp(), sock_write_timestamp()
 * are either inlined or only called for for sockets that actually request the
 * timestamp. Likewise, their callsites like sock_recv_errqueue,
 * sock_dequeue_err_skb(), __sock_recv_cmsgs(), ip_recv_error() and
 * ipv6_recv_error() do not seem to be called for most packets.
 *
 * For TCP, the tcp_recv_timestamp() seems like promising target, as it appears
 * to be called even for sockets that do not request timestamps, and appears
 * close to the end of tcp_recvmsg() when I think the data should be ready to
 * hand back to the user. It does not get the skb as an argument, but the RX
 * timestamp should be available in the first slot of the passed
 * scm_timestamping_internal tss. Will only work for entry point, as the
 * function will zero out the tss slots if no timestamp is requested.
 *
 * The tss slots themselves appear to be set by the tcp_recvmsg_locked()
 * function, so another alternative would be an fexit probe there.
 *
 * Another alternative could be tcp_update_recv_tstamps(), although a bit more
 * unclear if that's really called in suitable locations. For example, it may be
 * called multiple times for each read, as a read may consume multiple packets,
 * although maybe it's desireable to then get the time each packet got here?
 * The advantage is that it get's an skb as an arugment, making it very easy to
 * get the timestamp.
 *
 * For UDP, skb_consume_udp() seems like a good candiate, as it's called at the
 * very end of udp_recvmsg() and udpv6_recvmsg(), and nowhere else (on v6.12 at
 * least), and is passed the skb.
 *
 * It may also be worth considering also hooking __sock_recv_timestamp(), even
 * if it generally does not appear to be called unless the socket has requested
 * the timestamp. This will potentially catch some packets that the the other
 * two may miss. One can potentially filter out non-relevant socket types based
 * on the passed sock sk argument.
 */
SEC("fentry/tcp_update_recv_tstamps")
int BPF_PROG(netstacklat_tcp_recv_tstamps, struct sk_buff *skb, void *tss)
{
	// TODO - switch this to tcp_recv_timestamp instead
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_TCP_RECVMSG);
	return 0;
}


SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_current_netstacklat(skb, NETSTACKLAT_HOOK_UDP_RECVMSG);
	return 0;
}
