/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"UDPTime - Print time when UDP packet is received and the first 8 bytes";

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/err.h>
#include <net/if.h> // For if_nametoindex
#include <arpa/inet.h> // For inet_ntoa and ntohs

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <time.h>

#include "udptime.h" //common structs for user-space and BPF parts

#define DEFAULT_DPORT 123

#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?
#define PERF_POLL_TIMEOUT_MS 100

#define MAX_PATH_LEN 1024

#define MON_TO_REAL_UPDATE_FREQ                                                \
	(1 * NS_PER_SECOND) // Update offset between CLOCK_MONOTONIC and CLOCK_REALTIME once per second

// Store configuration values in struct to easily pass around
struct udptime_config {
	struct bpf_config bpf_config;
	char *object_path;
	char *event_map;
	char *bpf_prog_name;
	int xdp_flags;
	int ifindex;
	int ingress_prog_id;
	char ifname[IF_NAMESIZE];
	bool force;
};

static volatile int keep_running = 1;

static const struct option long_options[] = {
	{ "help",      no_argument,       NULL, 'h' },
	{ "interface", required_argument, NULL, 'i' }, // Name of interface to run on
	{ "port",      required_argument, NULL, 'p' }, // UDP dport to filter traffic for
	{ "force",     no_argument,       NULL, 'f' }, // Overwrite any XDP program currently running on the interface
	{ 0, 0, NULL, 0 }
};

/*
 * Copied from Jesper Dangaaard Brouer's traffic-pacing-edt example
 */
static void print_usage(char *argv[])
{
	int i;

	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c", long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

/*
 * Simple convenience wrapper around libbpf_strerror for which you don't have
 * to provide a buffer. Instead uses its own static buffer and returns a pointer
 * to it.
 *
 * This of course comes with the tradeoff that it is no longer thread safe and
 * later invocations overwrite previous results.
 */
static const char *get_libbpf_strerror(int err)
{
	static char buf[200];
	libbpf_strerror(err, buf, sizeof(buf));
	return buf;
}

static int parse_arguments(int argc, char *argv[], struct udptime_config *config)
{
	int err, opt;
	__u16 dport = 0;

	config->ifindex = 0;
	config->force = false;

	while ((opt = getopt_long(argc, argv, "hfi:p:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return -EINVAL;
			}
			strncpy(config->ifname, optarg, IF_NAMESIZE);

			config->ifindex = if_nametoindex(config->ifname);
			if (config->ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: %s\n",
					config->ifname, get_libbpf_strerror(err));
				return err;
			}
			break;
		case 'p':
			dport = atoi(optarg);
			if (!dport) {
				fprintf(stderr, "%s is not a valid port-number\n", optarg);
				return -EINVAL;
			}
			fprintf(stdout, "Filtering for UDP packets with dport %d\n", dport);
			config->bpf_config.dport = htons(dport); // Host to network byte order
			break;
		case 'f':
			config->force = true;
			config->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'h':
			printf("HELP:\n");
			print_usage(argv);
			exit(0);
		default:
			fprintf(stderr, "Unknown option %s\n", argv[optind]);
			return -EINVAL;
		}
	}

	if (config->ifindex == 0) {
		fprintf(stderr,
			"An interface (-i or --interface) must be provided\n");
		return -EINVAL;
	}

	return 0;
}

void abort_program(int sig)
{
	keep_running = 0;
}

static int set_rlimit(long int lim)
{
	struct rlimit rlim = {
		.rlim_cur = lim,
		.rlim_max = lim,
	};

	return !setrlimit(RLIMIT_MEMLOCK, &rlim) ? 0 : -errno;
}

static int init_rodata(struct bpf_object *obj, void *src, size_t size)
{
	struct bpf_map *map = NULL;
	bpf_object__for_each_map(map, obj) {
		if (strstr(bpf_map__name(map), ".rodata"))
			return bpf_map__set_initial_value(map, src, size);
	}

	// No .rodata map found
	return -EINVAL;
}

/*
 * Attempt to attach program in section sec of obj to ifindex.
 * If sucessful, will return the positive program id of the attached.
 * On failure, will return a negative error code.
 */
static int xdp_attach(struct bpf_object *obj, const char *sec, int ifindex,
		      __u32 xdp_flags)
{
	struct bpf_program *prog;
	int prog_fd, err;
	__u32 prog_id;

	if (sec)
		prog = bpf_object__find_program_by_title(obj, sec);
	else
		prog = bpf_program__next(NULL, obj);

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return prog_fd;

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err)
		return err;

	err = bpf_get_link_xdp_id(ifindex, &prog_id, xdp_flags);
	if (err) {
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		return err;
	}

	return prog_id;
}

static int xdp_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err)
		return err;

	if (!curr_prog_id) {
		return 0; // No current prog on interface
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id)
		return -ENOENT;

	return bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
}

/*
 * Returns time as nanoseconds in a single __u64.
 * On failure, the value 0 is returned (and errno will be set).
 */
static __u64 get_time_ns(clockid_t clockid)
{
	struct timespec t;
	if (clock_gettime(clockid, &t) != 0)
		return 0;

	return (__u64)t.tv_sec * NS_PER_SECOND + (__u64)t.tv_nsec;
}


static __u64 convert_monotonic_to_realtime(__u64 monotonic_time)
{
	static __u64 offset = 0;
	static __u64 offset_updated = 0;
	__u64 now_mon = get_time_ns(CLOCK_MONOTONIC);
	__u64 now_rt;

	if (offset == 0 ||
	    (now_mon > offset_updated &&
	     now_mon - offset_updated > MON_TO_REAL_UPDATE_FREQ)) {
		now_mon = get_time_ns(CLOCK_MONOTONIC);
		now_rt = get_time_ns(CLOCK_REALTIME); // Change to your NIC synced clock somehow?

		if (now_rt < now_mon)
			return 0;
		offset = now_rt - now_mon;
		offset_updated = now_mon;
	}
	return monotonic_time + offset;
}

static void print_udptimestamp(void *ctx, int cpu, void *data, __u32 data_size)
{
	const struct udp_timestamp *udp_ts = data;
	fprintf(stdout, "%llu %llu\n",
		convert_monotonic_to_realtime(udp_ts->arrival_time),
		udp_ts->packet_timestamp);
}

static void handle_missed_event(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu UDP timestamps on CPU %d\n", lost_cnt, cpu);
}

/*
 * Print out some hints for what might have caused an error while attempting
 * to attach an XDP program. Based on xdp_link_attach() in
 * xdp-tutorial/common/common_user_bpf_xdp.c
 */
static void print_xdp_error_hints(FILE *stream, int err)
{
	err = err > 0 ? err : -err;
	switch (err) {
	case EBUSY:
	case EEXIST:
		fprintf(stream, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
		break;
	case EOPNOTSUPP:
		fprintf(stream, "Hint: Native-XDP not supported\n");
		break;
	}
}

static int load_attach_bpfprog(struct bpf_object **obj,
				struct udptime_config *config)
{
	int err;

	// Open and load ELF file
	*obj = bpf_object__open(config->object_path);
	err = libbpf_get_error(*obj);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	err = init_rodata(*obj, &config->bpf_config,
			  sizeof(config->bpf_config));
	if (err) {
		fprintf(stderr, "Failed pushing port-number to BPF program: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	err = bpf_object__load(*obj);
	if (err) {
		fprintf(stderr, "Failed loading bpf program in %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	// Attach XDP prog to interface
	config->ingress_prog_id = xdp_attach(
		*obj, config->bpf_prog_name, config->ifindex, config->xdp_flags);
	if (config->ingress_prog_id < 0) {
		fprintf(stderr,
			"Failed attaching ingress XDP program on interface %s: %s\n",
			config->ifname, get_libbpf_strerror(err));
		print_xdp_error_hints(stderr, err);
		return config->ingress_prog_id;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0, detach_err;
	struct bpf_object *obj = NULL;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {
		.sample_cb = print_udptimestamp,
		.lost_cb = handle_missed_event,
	};

	struct udptime_config config = {
		.bpf_config = { .dport = DEFAULT_DPORT },
		.object_path = "udptime_kern.o",
		.event_map = "events",
		.bpf_prog_name = "xdp", 
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	};

	// Detect if running as root
	if (geteuid() != 0) {
		printf("This program must be run as root.\n");
		return EXIT_FAILURE;
	}

	// Increase rlimit
	err = set_rlimit(RLIM_INFINITY);
	if (err) {
		fprintf(stderr, "Could not set rlimit to infinity: %s\n",
			get_libbpf_strerror(err));
		return EXIT_FAILURE;
	}

	err = parse_arguments(argc, argv, &config);
	if (err) {
		fprintf(stderr, "Failed parsing arguments:  %s\n",
			get_libbpf_strerror(err));
		print_usage(argv);
		return EXIT_FAILURE;
	}


	err = load_attach_bpfprog(&obj, &config);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF program in %s\n",
			config.object_path);
		return EXIT_FAILURE;
	}

	// Set up perf buffer
	pb = perf_buffer__new(bpf_object__find_map_fd_by_name(obj,
							      config.event_map),
			      PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			config.event_map, get_libbpf_strerror(err));
		goto cleanup_attached_progs;
	}

	// Allow program to perform cleanup on Ctrl-C
	signal(SIGINT, abort_program);

	// Main loop
	while (keep_running) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
			if (keep_running) // Only print polling error if it wasn't caused by program termination
				fprintf(stderr,
					"Error polling perf buffer: %s\n",
					get_libbpf_strerror(-err));
			break;
		}
	}

	// Cleanup
	perf_buffer__free(pb);

cleanup_attached_progs:

	detach_err = xdp_detach(config.ifindex, config.xdp_flags,
					config.ingress_prog_id);
	if (detach_err)
		fprintf(stderr,
			"Failed removing ingress program from interface %s: %s\n",
			config.ifname, get_libbpf_strerror(detach_err));

	return (err != 0 && keep_running) || detach_err != 0;
}
