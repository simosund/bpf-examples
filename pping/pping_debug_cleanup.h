/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __PPING_DEBUG_CLEANUP_H
#define __PPING_DEBUG_CLEANUP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pping.h"

/*
 * Structs and functions that are only used for tracking the cleanup of the
 * packet timestamp and flow state maps.

 * Structs and contents of functions are guarded by ifdef DEBUGs to minimze
 * overhead, and kept in this file to keep the normal pping-related code
 * cleaner.
 */

#ifdef DEBUG
struct map_clean_stats {
	__u64 start_time;
	__u32 timeout_del;
	__u32 auto_del;
};

/*
 * The global variable keeps counts during the current cleaning cycle and is
 * updated continously. The array map keeps track of the history as well, but
 * is only updated at the end of each cleaning cycle.
 *
 * Both of them contain an entry for the packet timestamp map and the flow state
 * map (at DEBUG_PACKET_TIMESTAMP_MAP and DEBUG_FLOWSTATE_MAP)
 */

static volatile struct map_clean_stats current_clean_stats[2] = { 0 };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct stored_map_clean_stats);
	__uint(max_entries, 2);
} debug_clean_stats SEC(".maps");
#endif

static __always_inline void debug_increment_autodel(__u32 index)
{
#ifdef DEBUG
	current_clean_stats[index].auto_del += 1;
#endif
}

static __always_inline void debug_increment_timeoutdel(__u32 index)
{
#ifdef DEBUG
	current_clean_stats[index].timeout_del += 1;
#endif
}

static __always_inline void debug_update_mapclean_stats(void *key, void *value,
							__u64 seq_num,
							__u64 time, __u32 index)
{
#ifdef DEBUG
	struct stored_map_clean_stats *stored_stats;
	volatile struct map_clean_stats *cur_stats =
		&current_clean_stats[index];

	if (!key || !value) { // post final entry
		stored_stats = bpf_map_lookup_elem(&debug_clean_stats, &index);
		if (!stored_stats)
			return;

		if (cur_stats->start_time) { // At least one entry in map
			stored_stats->last_processed_entries = seq_num + 1;
			stored_stats->last_runtime =
				time - cur_stats->start_time;
		} else {
			stored_stats->last_processed_entries = 0;
			stored_stats->last_runtime = 0;
		}
		//update stored_stats
		stored_stats->last_timeout_del = cur_stats->timeout_del;
		stored_stats->last_auto_del = cur_stats->auto_del;
		stored_stats->tot_runtime += stored_stats->last_runtime;
		stored_stats->tot_processed_entries +=
			stored_stats->last_processed_entries;
		stored_stats->tot_timeout_del += stored_stats->last_timeout_del;
		stored_stats->tot_auto_del += stored_stats->last_auto_del;
		stored_stats->clean_cycles += 1;

		cur_stats->start_time = 0;
		cur_stats->timeout_del = 0;
		cur_stats->auto_del = 0;

	} else if (seq_num == 0) { // mark first entry
		cur_stats->start_time = time;
	}
#endif
}

#endif
