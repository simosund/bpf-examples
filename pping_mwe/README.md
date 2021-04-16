# What is this?
At this point I barley know. Started with me trying to set up a
minimal working example of the pping-code that seems to blow up the
number of instructions the verifier needs to process to the point that
it surpasses the 1 million limit. Now it's sort of a combination of
that and a bit of a testbed for experimenting with what blows up the
number of instructions.

## What I've found so far:
- Seems like it's a combination of my loop when parsing the TCP
  timestamps and the loop from parsing the IPv6 header that causes the
  size the blow up. It's fine with either or (especially just the TCP
  timestamp parsing), but when both are active at the same time the
  number of loops each of them does seem to result in a large number of
  extra processed instructions.

- I've also found that the logic in `parse_packet_identifier()` that
  swaps the saddr and daddr for ingress causes the tc program to become
  about 3 times as large as without it, whereas the XDP program is not
  affected (which is somewhat funny considering the XDP program is the
  one that actually swaps them).

- Decreasing the loop counts for either the TCP options
  (`MAX_TCP_OPTIONS`) or the IPv6 parsing (`IPV6_EXT_MAX_CHAIN`) has a
  very large effect on the number of instructions the verifier needs to
  process.
  
- Removing `__always_inline` from the functions has no effect at all
  (the compiler still inlines them).


## Files
- **pping_kern.c:** The "standalone" (except all the linux and libbpf
  imports) BPF-program code stripped down to the parts that seem to be
  the main issue. I've added some `#ifdef`s for the `INCLUDE_...`
  defines that are included in the beginning, which makes it easy to
  add/remove some parts of the program and see how it affects the
  number of instructions the verifier processes.
- **load_attach_progs.sh:** A simple script that opts as a replacement
  for the `bpf_egress_loader.sh` and userspace `pping.c` loaders for
  the ordinary pping application. Loads the object as well as
  attaching the XDP program using `bpftool`, and sets up a clsact
  qdisc and attaches the tc program using `tc`. Only really needed if
  you want to test that the BPF programs actually work, can otherwise
  just load the object file using `bpftool` to hit the verifier error.
- **trace_verifier.bt**: A simple bpftrace script that traces the
  central `do_check()` function of the verifier and prints out a
  couple of metrics from it, the primary one being the number of
  instructions processed.
