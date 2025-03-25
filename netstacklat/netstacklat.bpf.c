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
volatile const struct netstacklat_bpf_config user_config = {
	.interval = 10 * NS_PER_MS,
	.target = 1 * NS_PER_MS,
	.persist_through_empty = false,
	.npids = 0,
};

/* Helpers in maps.bpf.h require any histogram key to be a struct with a bucket member */
struct hist_key {
	u32 bucket;
};

struct standing_queue_state {
	ktime_t first_above;
	ktime_t last_above;
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_sock_standingqueue_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, HIST_NBINS);
	__type(key, u32);
	__type(value, u64);
} netstack_pidmatch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct standing_queue_state);
} netstack_sock_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FILTER_PIDS);
	__type(key, u32);
	__type(value, u8);
} netstack_pidfilter_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, u32);
	__type(value, u8);
} netstack_pidfilter_arr SEC(".maps");


static u32
get_exp2_histogram_bin_idx(u64 value, u32 max_bin)
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
	case NETSTACKLAT_HOOK_SOCK_STANDINGQUEUE:
		return &netstack_sock_standingqueue_seconds;
	case NETSTACKLAT_HOOK_PIDMATCH:
		return &netstack_pidmatch;
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

/*
 * Is there no more data to read from the socket?
 * For TCP socket it would be preferable to get the number of remaing bytes
 * from tcp_inq_hint(), but this doesn't seem to be called unless specifically
 * requsted by the application (and won't be accessible from existing hooks).
 *
 * So as a more generic solution, just check if the socket receive queue is
 * empty (no more skbs). Not sure if this is entierly accurate as UDP/TCP
 * sockets seem to use some other receive queues of their own as well, but
 * through some simple testing with bpftrace it seems to give reasonable
 * results with iperf for both TCP and UDP. Right now just checks if the
 * qlen member is 0. However, skb_queue_empty_lockless() instead checks
 * if the next points to itself, so should maybe do that if that's for
 * some reason safer in a lockless context?
 */
static bool sock_rxqueue_empty(struct sock *sk)
{
	return sk->sk_receive_queue.qlen == 0;
}

static ktime_t standing_socket_queue_duration(struct sock *sk, ktime_t latency)
{
	struct standing_queue_state *q_state;
	ktime_t now, duration = 0;

	/*
	 * I'm a bit confused about the bpf_sk_storage_get helper.
	 * The documentation
	 * (https://docs.ebpf.io/linux/helper-function/bpf_sk_storage_get/,
	 * https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) claims that
	 * only LSM hooks should send a pointer to a struct sock, and all other
	 * program types should instead send a pointer to a struct bpf_sock.
	 *
	 * However, sending the struct sock pointer directly appears to work,
	 * and from a brief look at the source code (net/core/bpf_sk_storage.c)
	 * it looks like it operates directly on struct socks. While some
	 * example programs do use struct bpf_sock (typically in instances where
	 * that's provided by the context), there are also some examples that
	 * use the it directly on struct sock in tracing contexts, e.g.
	 * tools/testing/selftests/bpf/progs/test_sk_storage_tracing.c.
	 */
	q_state = bpf_sk_storage_get(&netstack_sock_state, sk, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!q_state)
		return 0;

	if (latency < user_config.target ||
	    (!user_config.persist_through_empty && sock_rxqueue_empty(sk))) {
		if (q_state->first_above) {
			duration = q_state->last_above - q_state->first_above;
		}

		q_state->first_above = 0;
	} else {
		/*
		 * Could potentially reuse the "now" from the get_time_since()
		 * calculation to avoid an additional clock lookup. But a
		 * monotonic clock is really preferable when calculating
		 * durations.
		 */
		now = bpf_ktime_get_ns();

		q_state->last_above = now;
		if (!q_state->first_above)
			q_state->first_above = now;
	}

	return duration;
}

static bool single_pidmatch(u32 val)
{
	return val == user_config.pids[0];
}

static bool bsearch_pidmatch(u32 val)
{
	u32 mid, low = 0, high = user_config.npids - 1;

	while (low < high) {
		mid = (low + high) / 2;
		if (user_config.pids[mid] == val)
			return true;

		if (user_config.pids[mid] < val)
			low = mid + 1;
		else
			high = mid; // cannot do mid - 1, as that might underflow
	}

	return false;
}

static bool hash_pidmatch(u32 val)
{
	return bpf_map_lookup_elem(&netstack_pidfilter_hash, &val) != NULL;
}

static bool arr_pidmatch(u32 val)
{
	u8 *pid_ok;

	pid_ok = bpf_map_lookup_elem(&netstack_pidfilter_arr, &val);
	if (!pid_ok)
		return false;

	return *pid_ok > 0;
}

static bool match_pid(int pid)
{
	u64 start, duration;
	bool res;

	if (user_config.npids == 0)
		// No PID filter - all PIDs ok
		return true;

	start = bpf_ktime_get_ns();
	//res = single_pidmatch(pid);
	//res = bsearch_pidmatch(pid);
	res = arr_pidmatch(pid);
	//res = hash_pidmatch(pid);
	duration = bpf_ktime_get_ns() - start;

	record_latency(duration, NETSTACKLAT_HOOK_PIDMATCH);
	return res;
}

static bool match_current_task(void)
{
	__u32 tgid;

	if (user_config.npids == 0)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;
	return match_pid(tgid);
}

static void record_socket_read_latency(struct sock *sk, ktime_t tstamp,
				       enum netstacklat_hook hook)
{
	ktime_t latency, duration;

	if (!match_current_task())
		return;

	latency = time_since(tstamp);
	if (latency < 0)
		return;

	record_latency(latency, hook);

	duration = standing_socket_queue_duration(sk, latency);
	if (duration >= user_config.interval)
		record_latency(duration, NETSTACKLAT_HOOK_SOCK_STANDINGQUEUE);
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
	record_socket_read_latency(sk,
				   (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
				   NETSTACKLAT_HOOK_TCP_SOCK_READ);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_socket_read_latency(sk, skb->tstamp,
				   NETSTACKLAT_HOOK_UDP_SOCK_READ);
	return 0;
}
