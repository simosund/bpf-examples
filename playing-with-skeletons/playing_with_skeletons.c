/* SPDX-License-Identifier: GPL-2.0-or-later */

static const char *__doc__ =
	"Just testing using skeleton generation + different hooks";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Auto-generated skeleton: Contains BPF-object inlined as code */
#include "dummy_kern.skel.h"

int main(int argc, char *argv[])
{
	struct signalfd_siginfo sig_info;
	struct dummy_kern *obj;
	ssize_t read_bytes;
	sigset_t mask;
	int fd, err;

	fprintf(stdout, "%s\n", __doc__);

        sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	fd = signalfd(-1, &mask, 0);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	obj = dummy_kern__open_and_load();
        if (!obj) {
		fprintf(stderr, "Failure open/loading (%ld)\n",
			libbpf_get_error(obj));
		return EXIT_FAILURE;
	}

	err = dummy_kern__attach(obj);
	if (err) {
		fprintf(stderr, "Failure attaching (%ld)\n",
			libbpf_get_error(obj));
		return EXIT_FAILURE;
	}

	// Wait until user hits CTRL-C
	fprintf(stdout, "eBPF program dummy_prog is now attached\n");
	fprintf(stdout, "eBPF program will stay attached as long as this user space program is running\n");
	fprintf(stdout, "Hit CTRL-C to quit\n");
	read_bytes = read(fd, &sig_info, sizeof(sig_info));
	if (read_bytes != sizeof(sig_info))
		return EXIT_FAILURE;

	dummy_kern__destroy(obj);
	return EXIT_SUCCESS;
}
