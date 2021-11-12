# UDPTime
A simple program to extract a timestamp from a UDP packet

Whenever the interface receives a packet with the destination port specified (by
-p or --port) it will print out first the timestamp when it received the packet
(Unix timestamp in nano seconds) and then the timestamp stored in the packet
(the first 8 bytes of the UDP packet).

Assumes that the timestamp sent has the same byte order as the host machine
(ie. both sender and receiver should be little/big endian.).

## Output format
```shell
<arrival-time> <timestamp-in-packet>
```
## Clocks
Arrival time is captured by XDP in CLOCK_MONOTONIC, and then coverted to
CLOCK_REALTIME by the userspace program. Can potentially be converted to other
clocks. See the *convert_monotonic_to_realtime()* function.

## Files
- **udptime_user.c:** Userspace component - loads the XDP program and prints out
  the timestamps reported by the XDP program. You can use normal C-programming
  here.
- **udptime_kern.c:** The BPF program (specifically the XDP program). Contains
  the code running for each recieved packet. Is compiled into an .o file which
  the userspace program than loads and attaches to the XDP hook. Only a limited
  subset of C-programming is allowed here which is supported by BPF and the
  verifier.
- **udptime.h:** Short header file that simply contains the message struct that
  the XDP program sends to userspace each time it sucessfully parses a UDP
  packet.
