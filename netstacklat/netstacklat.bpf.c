/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "GPL";


volatile const __s64 TAI_OFFSET = (37LL * NS_PER_S);
volatile const struct netstacklat_bpf_config user_config = {
	.sq = {
		.interval = 10 * NS_PER_MS,
		.target = 1 * NS_PER_MS,
		.persist_through_empty = false,
	},
	.track_tcp_sq = true,
	.track_udp_sq = true,
	.filter_pid = false,
};

/*
 * Alternative definition of sk_buff to handle renaming of the field
 * mono_delivery_time to tstamp_type. See
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct sk_buff___old {
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	__u8 mono_delivery_time: 1;
} __attribute__((preserve_access_index));

struct standing_queue_state {
	ktime_t first_above;
	ktime_t last_above;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HIST_NBUCKETS * NETSTACKLAT_N_HOOKS);
	__type(key, struct hist_key);
	__type(value, u64);
} netstack_latency_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, u32);
	__type(value, u8);
} netstack_pidfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct standing_queue_state);
} netstack_sock_state SEC(".maps");

static u64 *lookup_or_zeroinit_histentry(void *map, const struct hist_key *key)
{
	u64 zero = 0;
	u64 *val;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	// Key not in map - try insert it and lookup again
	bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, key);
}

static u32 get_exp2_histogram_bucket_idx(u64 value, u32 max_bucket)
{
	u32 bucket = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bucket > 0 && 1ULL << bucket < value)
		bucket++;

	if (bucket > max_bucket)
		bucket = max_bucket;

	return bucket;
}

/*
 * Same call signature as the increment_exp2_histogram_nosync macro from
 * https://github.com/cloudflare/ebpf_exporter/blob/master/examples/maps.bpf.h
 * but provided as a function.
 *
 * Unlike the macro, only works with keys of type struct hist_key. The hist_key
 * struct must be provided by value (rather than as a pointer) to keep the same
 * call signature as the ebpf-exporter macro, although this will get inefficent
 * if struct hist_key grows large.
 */
static void increment_exp2_histogram_nosync(void *map, struct hist_key key,
					    u64 value, u32 max_bucket)
{
	u64 *bucket_count;

	// Increment histogram
	key.bucket = get_exp2_histogram_bucket_idx(value, max_bucket);
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		(*bucket_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = max_bucket + 1;
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		*bucket_count += value;
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
	struct hist_key key = { .hook = hook };
	increment_exp2_histogram_nosync(&netstack_latency_seconds, key, latency,
					HIST_MAX_LATENCY_SLOT);
}

static void record_latency_since(ktime_t tstamp, enum netstacklat_hook hook)
{
	ktime_t latency = time_since(tstamp);
	if (latency >= 0)
		record_latency(latency, hook);
}

static void record_skb_latency(struct sk_buff *skb, enum netstacklat_hook hook)
{
	if (bpf_core_field_exists(skb->tstamp_type)) {
		/*
		 * For kernels >= v6.11 the tstamp_type being non-zero
		 * (SKB_CLOCK_REALTIME) implies that skb->tstamp holds a
		 * preserved TX timestamp rather than a RX timestamp. See
		 * https://lore.kernel.org/all/20240509211834.3235191-2-quic_abchauha@quicinc.com/
		 */
		if (BPF_CORE_READ_BITFIELD(skb, tstamp_type) > 0)
			return;

	} else {
		/*
		 * For kernels < v6.11, the field was called mono_delivery_time
		 * instead, see https://lore.kernel.org/all/20220302195525.3480280-1-kafai@fb.com/
		 * Kernels < v5.18 do not have the mono_delivery_field either,
		 * but we do not support those anyways (as they lack the
		 * bpf_ktime_get_tai_ns helper)
		 */
		struct sk_buff___old *skb_old = (void *)skb;
		if (BPF_CORE_READ_BITFIELD(skb_old, mono_delivery_time) > 0)
			return;
	}

	record_latency_since(skb->tstamp, hook);
}

static bool filter_pid(u32 pid)
{
	u8 *pid_ok;

	if (!user_config.filter_pid)
		// No PID filter - all PIDs ok
		return true;

	pid_ok = bpf_map_lookup_elem(&netstack_pidfilter, &pid);
	if (!pid_ok)
		return false;

	return *pid_ok > 0;
}

static bool filter_current_task(void)
{
	__u32 tgid;

	if (!user_config.filter_pid)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;
	return filter_pid(tgid);
}

/*
 * Is there no more data to read from the socket?
 * For TCP socket it would be preferable to get the number of remaing bytes
 * from tcp_inq_hint(), but this doesn't seem to be called unless specifically
 * requsted by the application (and won't be accessible from existing hooks).
 *
 * As a more generic solution, just check if the socket receive queue is
 * empty (no more skbs). Not sure if this is entierly accurate as UDP/TCP
 * sockets seem to use some other receive queues of their own as well, but
 * through some simple testing with bpftrace it seems to give reasonable
 * results with iperf for both TCP and UDP.
 */
static bool sock_rxqueue_empty(struct sock *sk)
{
	/*
	 * Right now just checks if the qlen member is 0. However,
	 * skb_queue_empty_lockless() checks if next points to itself, so that
	 * might perhaps be a safer option when used in a lockless context.
	 */
	return sk->sk_receive_queue.qlen == 0;
}

/*
 * Detect how long the latency at the socket layer has been above the latency
 * target using an algorithm similar to CoDel.
 */
static ktime_t socket_standingqueue_duration(struct sock *sk, ktime_t latency)
{
	struct standing_queue_state *q_state;
	ktime_t now, duration = 0;

	q_state = bpf_sk_storage_get(&netstack_sock_state, sk, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!q_state)
		return 0;

	if (latency < user_config.sq.target ||
	    (!user_config.sq.persist_through_empty && sock_rxqueue_empty(sk))) {
		if (q_state->first_above) {
			duration = q_state->last_above - q_state->first_above;
		}

		q_state->first_above = 0;
	} else {
		/*
		 * Reusing the same "now" timestamp used to calculate the
		 * latency would be slightly more efficent, but having a
		 * monotonic clock is preferable.
		 */
		now = bpf_ktime_get_ns();

		q_state->last_above = now;
		if (!q_state->first_above)
			q_state->first_above = now;
	}

	return duration;
}

static void detect_socket_standingqueue(struct sock *sk, ktime_t latency,
					enum netstacklat_hook sq_hook)
{
	ktime_t duration;

	duration = socket_standingqueue_duration(sk, latency);
	if (duration >= user_config.sq.interval)
		record_latency(duration, sq_hook);
}

static void record_socket_latency(struct sock *sk, ktime_t tstamp,
				  enum netstacklat_hook hook, bool track_sq,
				  enum netstacklat_hook sq_hook)
{
	ktime_t latency;

	if (!filter_current_task())
		return;

	latency = time_since(tstamp);
	if (latency < 0)
		return;

	record_latency(latency, hook);

	if (track_sq)
		detect_socket_standingqueue(sk, latency, sq_hook);
}

SEC("fentry/ip_rcv_core")
int BPF_PROG(netstacklat_ip_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/ip6_rcv_core")
int BPF_PROG(netstacklat_ip6_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/tcp_v4_rcv")
int BPF_PROG(netstacklat_tcp_v4_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/tcp_v6_rcv")
int BPF_PROG(netstacklat_tcp_v6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/udp_rcv")
int BPF_PROG(netstacklat_udp_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fentry/udpv6_rcv")
int BPF_PROG(netstacklat_udpv6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fexit/tcp_data_queue")
int BPF_PROG(netstacklat_tcp_data_queue, struct sock *sk, struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED);
	return 0;
}

SEC("fexit/udp_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udp_queue_rcv_one_skb, struct sock *sk,
	     struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}

SEC("fexit/udpv6_queue_rcv_one_skb")
int BPF_PROG(netstacklat_udpv6_queue_rcv_one_skb, struct sock *sk,
	     struct sk_buff *skb)
{
	record_skb_latency(skb, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}

SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	struct timespec64 *ts = &tss->ts[0];
	record_socket_latency(sk, (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			      NETSTACKLAT_HOOK_TCP_SOCK_READ,
			      user_config.track_tcp_sq,
			      NETSTACKLAT_HOOK_TCP_STANDINGQUEUE);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_socket_latency(sk, skb->tstamp, NETSTACKLAT_HOOK_UDP_SOCK_READ,
			      user_config.track_udp_sq,
			      NETSTACKLAT_HOOK_UDP_STANDINGQUEUE);
	return 0;
}
