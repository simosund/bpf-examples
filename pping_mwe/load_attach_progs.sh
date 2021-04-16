#!/bin/bash

pinfolder=/sys/fs/bpf/pping_testing
objectfile=pping_kern.o
device=test123

echo -e "This horrible script does zero error handling and requires that you run it as sudo\n"

if [[ $1 == "--remove" ]]; then
   echo "Detaching XDP program"
   bpftool net detach xdp dev "$device"

   echo "Tearing down tc qdisc"
   tc qdisc del dev "$device" clsact

   echo "Removing pinned programs"
   rm -r "$pinfolder"
else
    echo "Loading and pinning programs to $pinfolder"
    bpftool prog loadall "$objectfile" "$pinfolder"

    echo "Attaching XDP program"
    bpftool net attach xdp pinned "$pinfolder/xdp" dev "$device"

    echo "Setting up and attaching tc program"
    tc qdisc add dev "$device" clsact
    tc filter add dev "$device" pref 2 handle 2 \
       egress bpf da pinned "$pinfolder/classifier"
    echo "Done"
fi
