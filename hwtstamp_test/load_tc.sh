#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

dev=$1
detach=$2

# First remove clsact to clear any previous tc-BPF progs
tc qdisc del dev $dev clsact 2> /dev/null

if [[ "$detach" != "--detach" ]]; then
    tc qdisc add dev $dev clsact
    tc filter add dev $dev pref 2 handle 2 ingress bpf da obj hwtest.bpf.o
fi
