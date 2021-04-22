# What is this?
This started with me trying to set up a minimal working example of the
pping-code that seems to blow up the number of instructions the
verifier needs to process to the point that it surpasses the 1 million
limit. Now it's sort of a combination of that and a bit of a testbed
for experimenting with what blows up the number of instructions.

## The problem
My pping implementation uses two BPF programs, one for egress traffic
that's attached to a clsact qdisc using tc, and the other one for
ingress traffic attached to XDP. Originally these two BPF programs
were kept in separate files (`pping_kern_xdp` and `pping_kern_tc`),
but it was decided to move both of them to a single file
(`pping_kern`) to simplify the setup somewhat.

However, after moving the two programs to the same file (with no
changes to the actual code itself), the BPF verifier started
complaining that the egress/tc program was too large (over 1 million
instructions).

## The explanation: Short version
The current hypothesis is that the combination of the loop for parsing
IPv6 extension headers (in `skip_ip6hdrext()`) and the loop for
parsing TCP options (in `parse_tcp_ts()`) together create a
combinatorial explosion of branches that the verifier has to go
through, and while doing that ends up processing over 1 million
instructions (even if no single branch is that long).

## The explanation: Longer version
From my understanding of the verifier, when it verifies the program it
has to go through every potential branch to verify that the program is
safe. Originally, when the verifier wouldn't accept programs over 4k
instructions it would still process up to 64k instructions by going
through different branches, although even then it could reject
programs that were shorter than 4k instructions if they had a large
number of branches. Now the maximum size of programs has been
increased to 1 million instructions, although the verifier also "only"
seems to process at most 1 million instructions while going through
all the branches. So programs that are much smaller than 1 million
instructions can still be rejected if there are many potential
branches.

To find what seems to cause the verifier to process over 1 million
instructions for the seemingly relatively simple pping program, I've tried
to strip out most parts of the program that don't seem to have a large
effect on the number of instructions the verifier needs to
process. I've then further studied how removing certain parts of the
program affects the number of instructions the verifier needs to
process (some of which can easily be toggled through the `INCLUDE_...`
defines in the beginning of `pping_kern.c`).

The number of instructions that the verifier needs to process for
various variations of the program are contained in the table
below. Default refers to the full example as is, whereas the other
lines refer to the exemple except with the modification described by
the line. Separate files refers to if the XDP and tc programs were
kept in separate files instead (which in this case has been achieved
by removing one of the programs from the example at a time and loading
them).

| Prog version                  | XDP prog | TC prog |
|-------------------------------|---------:|--------:|
| Default                       |     599k |    > 1m |
| Separate files                |     462k |    461k |
| No TCP options parsing        |      16k |     47k |
| Only 5 TCP opt. loops         |     165k |    520k |
| Only 1 TCP opt. loop          |      25k |     80k |
| No IPv6 path                  |       9k |     27k |
| Only 3 IPv6 ext. loops        |     116k |    317k |
| Only 1 IPv6 ext. loop         |      17k |     51k |
| No swap saddr/daddr           |     603k |    603k |
| No \__always_inline           |     599k |    > 1m |
| noinline for loop funcs.      |     381k |    > 1m |
| Separate files + no TCP opts. |      14k |     13k |
| Separate files + no IPv6      |       9k |     8 k |
| Separate files + no swap      |     462k |    461k |
| No swap + no TCP opts         |      16k |     16k |
| No swap + no IPv6             |       9k |      9k |
| No TCP opt + no IPv6          |      272 |     716 |

Based on these results, I've drawn the following conclusions:

- Seems like it's a combination of my loop when parsing the TCP
  timestamps and the loop from parsing the IPv6 header that causes the
  size to blow up. It's fine with either or (especially just the TCP
  timestamp parsing), but when both are active at the same time the
  number of loops each of them does seem to result in a large number of
  extra processed instructions. This if probably further escalated by
  there being a fair amount of different branches within both of these
  loops.

- Decreasing the loop counts for either the TCP options
  (`MAX_TCP_OPTIONS`) or the IPv6 parsing (`IPV6_EXT_MAX_CHAIN`) has a
  very large effect on the number of instructions the verifier needs
  to process.

- Splitting up the program into separate files seems to drastically
  reduce the number of instructions processed, at least for the full
  program. The reason for this seems to be that when kept in separate
  files, the compiler will inline all the functions, whereas if kept
  in the same file, the compiler will actually call the
  `parse_packet_indentifier()` function (all other functions will be
  inlined inside this one). If one keeps the programs in the separate
  files but forces the compiler to not inline the call (by adding
  `__attribute__((noinline))` to `parse_packet_identifier()`), then
  one will get identical results as when the programs are kept in the
  same file. When keeping both programs in the same file it doesn't
  seem possible to actually get the `parse_packet_identifier()`
  function inlined, as even if it's declared as `__always_inline`, the
  compiler will still generate BPF bytecode where it's called as a
  function.

- I've also found that the logic in `parse_packet_identifier()` that
  swaps the saddr and daddr for ingress causes the tc program to
  become about 3 times as large as without it, whereas the XDP program
  is not affected. Without this logic the XDP and tc programs are of
  roughly the same size. However if the programs are kept in separate
  files then the tc program does not see the x3 increase (possibly
  because the compiler figures out that it's always egress, and
  therefore only keeps the egress branch of the if-statement).
  
- Removing `__always_inline` from all the functions has no effect at
  all (the compiler still inlines them).

- Adding `__attribute__((noinline))` to the two functions containing
  the loops seems to help the situation somewhat (XDP program goes
  down from 599k to 381k processed instructions), but is not enough to
  get the tc program down to under 1 million processed instructions.

## Solutions
There are a few simple solutions that can be employed for now, however
as the program grows more complex in the future this problem might
reappear.

- Separate the two BPF programs into different files again. The main
  drawback with this is that it makes the loading slightly more
  complicated and requires reverting back to multiple files for the
  BPF code.

- Reduce the maximum number of IPv6 extensions parsed (i.e. lower
  `IPV6_EXT_MAX_CHAIN`). From what I've gathered IPv6 extensions are
  very unusual in the wild, so reducing the number of extensions
  parsed to ex 3 should not be much of a limitation.

- Reduce the maximum number of TCP options parsed (i.e. lower
  `MAX_TCP_OPTIONS`). I think it's quite unusual with packets that
  would require 10 options to be parsed to find the TCP
  timestamp. However, while 10 "actual" options are very unlikely, the
  "NOP" option may be used for alignment of other options and may
  therefore add a bit to the count.

## Files
- **pping_kern.c:** The "standalone" (except all the linux and libbpf
  imports) BPF-program code stripped down to the parts that seem to be
  the main issue. I've added some `#ifdef`s for the `INCLUDE_...`
  defines in the beginning, which makes it easy to add/remove some
  parts of the program and see how it affects the number of
  instructions the verifier processes.
- **load_attach_progs.sh:** A simple script that opts as a replacement
  for the `bpf_egress_loader.sh` and userspace `pping.c` loaders for
  the ordinary pping application. Loads the object file as well as
  attaching the XDP program using `bpftool`, and sets up a clsact
  qdisc and attaches the tc program using `tc`. Only really needed if
  you want to test that the BPF programs actually work, can otherwise
  just load the object file using `bpftool` to see how many
  instructions the verifier processes.
- **trace_verifier.bt**: A simple bpftrace script that traces the
  central `do_check()` function of the verifier and prints out a
  couple of metrics from it, the primary one being the number of
  instructions processed.

## Environment
The system I've tested this on runs Ubuntu 20.10 with kernel version
5.8, and the code has been compiled using clang/LLVM 11.0.

```
$ uname -r
5.8.0-50-generic

$ clang --version
Ubuntu clang version 11.0.0-2
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```
