/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"hwtest - Test skb->tstamp members";

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
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


#define MAX_PATH_LEN 1024



// Store configuration values in struct to easily pass around
struct hwtest_config {
	struct bpf_tc_opts tc_ingress_opts;
	char *object_path;
	char *ingress_prog;
	int ifindex;
	int ingress_prog_id;
	char ifname[IF_NAMESIZE];
	bool force;
	bool created_tc_hook;
};

static volatile sig_atomic_t keep_running = 1;

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "interface",        required_argument, NULL, 'i' }, // Name of interface to run on
	{ "force",            no_argument,       NULL, 'f' }, // Overwrite any existing XDP program on interface, remove qdisc on cleanup
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

static int parse_arguments(int argc, char *argv[], struct hwtest_config *config)
{
	int err, opt;

	config->ifindex = 0;
	config->force = false;

	while ((opt = getopt_long(argc, argv, "hfi:",
				  long_options, NULL)) != -1) {
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
					config->ifname,
					get_libbpf_strerror(err));
				return err;
			}
			break;
		case 'f':
			config->force = true;
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

/*
 * Will attempt to attach program at section sec in obj to ifindex at
 * attach_point.
 * On success, will fill in the passed opts, optionally set new_hook depending
 * if it created a new hook or not, and return the id of the attached program.
 * On failure it will return a negative error code.
 */
static int tc_attach(struct bpf_object *obj, int ifindex,
		     enum bpf_tc_attach_point attach_point,
		     const char *prog_name, struct bpf_tc_opts *opts,
		     bool *new_hook)
{
	int err;
	int prog_fd;
	bool created_hook = true;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);

	err = bpf_tc_hook_create(&hook);
	if (err == -EEXIST)
		created_hook = false;
	else if (err)
		return err;

	prog_fd = bpf_program__fd(
		bpf_object__find_program_by_name(obj, prog_name));
	if (prog_fd < 0) {
		err = prog_fd;
		goto err_after_hook;
	}

	opts->prog_fd = prog_fd;
	opts->prog_id = 0;
	err = bpf_tc_attach(&hook, opts);
	if (err)
		goto err_after_hook;

	if (new_hook)
		*new_hook = created_hook;
	return opts->prog_id;

err_after_hook:
	/*
	 * Destroy hook if it created it.
	 * This is slightly racy, as some other program may still have been
	 * attached to the hook between its creation and this error cleanup.
	 */
	if (created_hook) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
	}
	return err;
}

static int tc_detach(int ifindex, enum bpf_tc_attach_point attach_point,
		     const struct bpf_tc_opts *opts, bool destroy_hook)
{
	int err;
	int hook_err = 0;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_info, .handle = opts->handle,
			    .priority = opts->priority);

	// Check we are removing the correct program
	err = bpf_tc_query(&hook, &opts_info);
	if (err)
		return err;
	if (opts->prog_id != opts_info.prog_id)
		return -ENOENT;

	// Attempt to detach program
	opts_info.prog_fd = 0;
	opts_info.prog_id = 0;
	opts_info.flags = 0;
	err = bpf_tc_detach(&hook, &opts_info);

	/*
	 * Attempt to destroy hook regardsless if detach succeded.
	 * If the hook is destroyed sucessfully, program should
	 * also be detached.
	 */
	if (destroy_hook) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		hook_err = bpf_tc_hook_destroy(&hook);
	}

	err = destroy_hook ? hook_err : err;
	return err;
}

static int load_attach_bpfprogs(struct bpf_object **obj,
				struct hwtest_config *config)
{
	int err;
	config->created_tc_hook = false;

	// Open and load ELF file
	*obj = bpf_object__open(config->object_path);
	err = libbpf_get_error(*obj);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	err = bpf_object__load(*obj);
	if (err) {
		fprintf(stderr, "Failed loading bpf programs in %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	// Attach ingress prog
	err = tc_attach(*obj, config->ifindex, BPF_TC_INGRESS,
			config->ingress_prog, &config->tc_ingress_opts,
			&config->created_tc_hook);
	if (err < 0) {
		fprintf(stderr,
			"Failed attaching ingress BPF program on interface %s: %s\n",
			config->ifname, get_libbpf_strerror(err));
		goto ingress_err;
	}
	config->ingress_prog_id = err;


	return 0;

ingress_err:
	bpf_object__close(*obj);
	return err;
}

int main(int argc, char *argv[])
{
	int err = 0, detach_err;
	struct bpf_object *obj = NULL;

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_ingress_opts);

	struct hwtest_config config = {
		.object_path = "hwtest.bpf.o",
		.ingress_prog = "hwtest_tc",
		.tc_ingress_opts = tc_ingress_opts,
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

	// Allow program to perform cleanup on Ctrl-C
	signal(SIGINT, abort_program);
	signal(SIGTERM, abort_program);

	err = load_attach_bpfprogs(&obj, &config);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF programs in %s\n",
			config.object_path);
		return EXIT_FAILURE;
	}

	// Main loop
	while (keep_running) {
		usleep(100000);
	}

	detach_err = tc_detach(config.ifindex, BPF_TC_INGRESS,
			       &config.tc_ingress_opts,
			       config.force && config.created_tc_hook);
	if (detach_err)
		fprintf(stderr,
			"Failed removing ingress program from interface %s: %s\n",
			config.ifname, get_libbpf_strerror(detach_err));
	err = err ? err : detach_err;

	bpf_object__close(obj);

	return err;
}
