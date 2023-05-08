// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

char _license[] SEC("license") = "GPL";

SEC("classifier")
int hwtest_tc(struct __sk_buff *skb)
{
	bpf_printk("ktime_get_ns: %llu", bpf_ktime_get_ns());
	bpf_printk("skb: tstamp: %llu, hwtstamp: %llu, tstamp_type: %u\n",
		   skb->tstamp, skb->hwtstamp, skb->tstamp_type);
	return TC_ACT_UNSPEC;
}
