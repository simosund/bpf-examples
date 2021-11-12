/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UDPTIME_H
#define UDPTIME_H

#include <linux/types.h>
#include <linux/in6.h>
#include <stdbool.h>

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL

struct bpf_config {
	__u16 dport;
};

struct udp_timestamp {
	__u64 arrival_time; // When packet reached XDP hook (CLOCK_MONOTONIC)
	__u64 packet_timestamp; // First 8 bytes of UDP packet
};

#endif
