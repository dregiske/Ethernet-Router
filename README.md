# pa2a-starter

## Info

Name: Andre Giske

PID: A17918324

Email: agiske@ucsd.edu

## Description and Overview

Describe in brief what files you changed and what they should do:

- `sr_router.c` — packet entry point and all packet logic. `sr_handlepacket` length checks the buffer, reads the Ethernet type, and routes to either `handle_arp` or `handle_ip`. Unknown ether types are dropped. `send_arp_request` builds a broadcast ARP request to find who has `target_ip`. `send_icmp_error` is a single helper for all three error types.

- `sr_router.h` — added prototypes for the two helpers exposed to `sr_arpcache.c`.

- `sr_arpcache.c` — implemented `sr_arpcache_sweepreqs` and the request retry/timeout helper. `sr_arpcache_sweepreqs` walks the request queue, saves request's `next` pointer incase it gets destroyed, and calls on `handle_arpreq`. This function then handles all outstanding request cases.

### Testing

Validated inside the container by running POX, Mininet, and
`./sr -l test.pcap`, then running:

- `client ping` to each of the three router IPs (10.0.1.1, 192.168.2.1, 172.64.3.1)
- `client ping` to both servers (192.168.2.2, 172.64.3.10) to verify the full forwarding path
- `server1 ping server2` to verify routing across two non client subnets
- `client ping --ttl=1 ...` to check ICMP time-exceeded
- `client ping 8.8.8.8` to verify ICMP unreachable
- Closed a server interface and pinging it to verifies the 5 retry ARP timeout and ICMP host unreachable

An automated unittest suite at `tests/test_pa2.py` covers the same behaviors and a few extra edge cases.

# pa2b-starter

## Description and Overview

Pretty much all changes are localized to `sr_router.c`, including: ARP caching, longest prefix match routing, and handling for non-ICMP protocols on top of IP.

- `sr_router.c` - added `lpm`, new helper implementing Longest Prefix Match. This function walks the routing table and returns the entry whose masked destination matches the destination IP with the most specific (longest) mask. `handle_ip` has a couple big changes:

1. TCP/UDP packets addressed to one of the router's interfaces now generate an ICMP port unreachable (type 3, code 3), which is what makes traceroute to the router work. Other non-ICMP protocols are still ignored.
2. The next hop is resolved via `lpm`, with a fallback to the destination IP when the route's gateway is `0.0.0.0`. We ask the ARP cache first for a hit/miss. On a hit, the L2 addresses are rewritten and the frame is forwarded immediately. On a miss the packet queued and an ARP request sent.
