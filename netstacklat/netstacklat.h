/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NETSTACKLAT_H
#define NETSTACKLAT_H

/*
 * Highest number of useable bins in the histogram.
 * The valid range for storing bin counts is thus idx 0 - HIST_MAX_BINS - 1.
 * Note that this does NOT include the additional "sum bin" that is stored
 * at the end of the histogram, so maps may contain a total of
 * HIST_MAX_BINS + 1 elements.
 */
#define HIST_MAX_BINS 256

#define NS_PER_S 1000000000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#ifndef max
#define max(a, b)                   \
	({                          \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a > _b ? _a : _b;  \
	})
#endif

enum netstacklat_hook {
	NETSTACKLAT_HOOK_INVALID = 0,
	NETSTACKLAT_HOOK_TCP_V4_DO_RCV,
	NETSTACKLAT_HOOK_TCP_DATA_QUEUE,
	NETSTACKLAT_HOOK_UDP_QUEUE_RCV_ONE,
	NETSTACKLAT_N_HOOKS,
};

#endif

