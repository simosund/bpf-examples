/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>

char _license[] SEC("license") = "GPL";

const volatile int my_config = 0;

SEC("tp/syscalls/sys_enter_connect")
int hello(void *ctx)
{
	/*
	const char message[] = "D0_Y0U_KN0W_BPF?";
	int idx = 0;

	for (idx = 0; idx < sizeof(message) - 1; idx++) {
		bpf_printk("%c\n", *(message + idx));
	}
	*/

	/* bpf_printk("My dummy prog is running\n"); */
	int a;
	if (my_config)
		a = 123;
	else
		a = 0;
	bpf_printk("a = %d\n", a);

	return 0;
}
