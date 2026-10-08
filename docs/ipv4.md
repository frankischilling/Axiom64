# IPv4, ARP, routing, and ping

The initial IPv4 host path runs over [virtio-net and QEMU e1000](network.md). It supports static addresses, loopback, connected and explicit routes, bounded ARP resolution, kernel ICMP echo replies, and Linux raw ICMP sockets. BusyBox `ifconfig`, route add/delete, and numeric `ping` exercise the guest implementation. DHCP, DNS, TCP/UDP data, downloads, IPv6, and complete IPv4 conformance remain required by the [networking roadmap](feature-roadmap.md).

## Ownership and progress

`kernel/net/ipv4/core.cpp` owns configuration, 32 explicit routes, 128 interface/address-scoped neighbors, and 32 pending outputs. `socket.cpp` owns raw ICMP descriptions and receive queues. `kernel/net/ioctl.cpp` translates the Linux interface and legacy route structures. Wire helpers stay within the IPv4 module.

Output owns a heap copy of the complete Ethernet/IP frame before waiting for ARP or driver capacity. A successful send means the bounded queue accepted the bytes. The driver then copies the frame into its own DMA storage and retains it until completion. Closing the socket detaches pending error/accounting references; accepted output keeps its bytes without referring to a reused socket slot. RX validates its bounds and copies each selected datagram into an independent listener queue before recycling the hardware buffer.

Polling runs with serialized callers on the current single CPU, including the scheduler's all-tasks-blocked loop. It advances ARP retries, output deadlines, driver completions, and receive delivery. Protocol callbacks enqueue replies instead of recursively transmitting from RX. Shutdown frees protocol outputs before stopping the adapters. SMP, interrupt-driven networking, and reset recovery remain planned.

Neighbors retain a reachable mapping for five minutes. Resolution attempts a request immediately and twice more at one-second intervals, then reports `EHOSTUNREACH` at about three seconds. Failed mappings expire after one second. Replacement selects an available or least-recently-used entry while preserving neighbors referenced by unresolved output. A validated request or reply can refresh an existing peer's MAC. ARP validates hardware/protocol types, address sizes, operation, length, source MAC/IP, and reply target addresses. Zero sender IP is accepted for a request probe and never cached.

Pending IP output has a four-second bound; generated ARP replies have a one-second bound. Continued TX backpressure expires a ready output with `ENOBUFS`; failed resolution reports `EHOSTUNREACH`. Each raw socket tracks at most 65536 pending IP bytes. These are the initial bounded policies, without a complete Linux asynchronous error queue.

## Configuration and routing

Ethernet interfaces start administratively down and without an IPv4 address. The fixed `lo` interface has index 9, address `127.0.0.1/8`, and MTU 65536; it is a logical interface rather than an Ethernet adapter. Local addresses use the same IPv4/ICMP validation path without hardware transmission.

The x86-64 Linux `ifreq` controls support address, netmask, broadcast, name/index, MAC, flags, and MTU. Masks must be contiguous; invalid updates leave the configuration intact. Address zero disables that interface's IPv4 configuration. A mask shorter than /31 derives the directed broadcast unless explicitly supplied; /31 and /32 have no directed broadcast. Reconfiguration clears that interface's neighbor cache and rejects its pending output with `ENETDOWN`.

`SIOCGIFCONF` returns whole 40-byte entries for assigned Ethernet addresses and loopback. A null buffer queries the required size. Configuration-only `AF_INET/SOCK_DGRAM` and `AF_UNIX/SOCK_DGRAM` descriptors support the interface ioctl path used by libc/BusyBox. Their data and socket-lifecycle operations return `EOPNOTSUPP`; UDP and Unix datagram transport are still required.

`SIOCADDRT` and `SIOCDELRT` implement the initial 120-byte Linux `rtentry` contract: connected routes, on-link routes, gateways, default routes, host routes, and metrics. Selection chooses the longest matching prefix, then the lower metric. An omitted device is inferred from a directly connected destination or gateway. A gateway must be a nonlocal unicast address on the selected interface's subnet. Duplicate routes, missing routes, invalid masks/families, and unreachable gateways return explicit errors. Netlink, `/proc/net/route`, aliases, policy routing, and route-listing support remain planned.

With a matching controlled peer connected to `eth0`, guest commands include:

```sh
ifconfig eth0 10.23.1.2 netmask 255.255.255.0 up
route add default gw 10.23.1.1 dev eth0
ping -n -c 2 -w 5 -I eth0 10.23.1.1
route del default gw 10.23.1.1 dev eth0
```

Physical carrier and `IFF_UP` are independent. Carrier or administrative down rejects wire output with `ENETDOWN`; a permanently failed bound adapter reports `POLLERR` and `EIO`. Loopback remains usable during a physical link outage.

## IPv4 and ICMP validation

Input requires IPv4 version 4, a 20-byte header, a valid header checksum, a bounded total length, nonzero TTL, supported flag forms, valid source addressing, and a local or accepted broadcast destination. Ethernet padding is trimmed to the IP total length. Traffic from a NIC cannot impersonate loopback. Options, fragments, and the reserved flag are rejected; forwarding and reassembly are not implemented.

Output builds its own 20-byte header, checksum, identifier, TTL, and DF flag. The IP header counts toward the interface MTU; oversized output returns `EMSGSIZE`. The supported MTU-discovery settings retain DF, without a learned path-MTU cache. Limited and directed broadcasts use the Ethernet broadcast destination and require `SO_BROADCAST`. Multicast, TOS controls, IPv6, and general IP options remain planned.

The ICMP handler checks payload length and checksum before answering a local unicast echo request. Echo replies preserve the identifier, sequence, and payload. It does not answer broadcast echo requests or recursively generate errors for ICMP errors. Unknown local unicast protocols can generate a rate-limited protocol-unreachable response quoting the original header and first eight payload bytes. Valid destination-unreachable and parameter-problem quotes can report matching connected raw-socket errors; malformed or unrelated quotes are ignored.

Raw ICMP listeners receive the complete validated IPv4 datagram before the ICMP handler checks its payload checksum, matching the Linux raw-observer ordering. A raw program can therefore see an invalid ICMP checksum that the kernel handler rejects. Kernel validation and raw observation are tested separately.

## Raw ICMP socket contract

`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` supports close-on-exec and nonblocking flags, bind/connect/disconnect, duplicate/fork lifetime, address queries, `read`/`write`, vectors, and send/receive message calls. Received data includes the IP header. Source `sockaddr_in` contains `AF_INET`, port zero, and the source IPv4 address. The raw socket's local port metadata is the protocol number; the supplied connect port is peer-query metadata and does not affect transmission. As on the compared Linux path, a zero peer port makes `getpeername` report `ENOTCONN`.

Each listener holds at most 32 datagrams and 65536 bytes, dropping new arrivals when either bound is reached without affecting other listeners. `SO_RCVBUF` and `SO_SNDBUF` double the requested size, clamp it to the supported bound, and impose a 2048-byte minimum. `SO_BINDTODEVICE`, `SO_BROADCAST`, `IP_TTL`, the supported DF policies, and `ICMP_FILTER` are implemented. Bind, peer, interface, and ICMP filters apply independently.

Receive supports `MSG_PEEK`, `MSG_TRUNC`, and `MSG_DONTWAIT`; sends also accept `MSG_NOSIGNAL`. Poll/epoll and `FIONREAD` expose queue state. An ordinary failed receive copy consumes the selected datagram; a failed peek retains it. This behavior is checked against Linux and leaves the separate packet-socket contract intact. Blocking I/O captures vectors, addresses, and TX bytes and retains the original description through close/reuse. Socket errors take precedence over queued input; a failed `SO_ERROR` copy does not clear the pending error.

TCP, UDP data, other raw protocols, listen/accept/shutdown, deadlines, ancillary data, `IP_HDRINCL`, error queues, and other unsupported options return explicit errors. Current tasks run as root. Accounts, permission enforcement, and secure randomness remain prerequisites for exposing services.

## Verification

```sh
make test-ipv4
python3 scripts/ipv4_test.py --firmware bios --transport modern
python3 scripts/ipv4_test.py --firmware both --transport legacy
python3 scripts/ipv4_test.py --firmware both --fault
sudo ./build/ipv4-tests --loopback
```

The final command runs the common loopback/raw-socket checks on the Linux build host for comparison. The guest matrix has eight boots: BIOS/UEFI and modern/legacy virtio, each with virtio-net and e1000 together, followed by the same four cases with an isolated virtio RX identity fault. Results accumulate in `build/ipv4-results.json`; logs and GDB commands use `build/ipv4-*`. A standalone invocation replaces its result file with that invocation's cases.

Independent loopback TCP peers handle QEMU's Ethernet framing. They validate interface-specific MACs, ARP fields/padding, IPv4 route/source/destination/length/checksum/TTL/DF, ICMP checksums, and deterministic payloads. They answer real guest requests; they do not run guest socket operations or substitute for the kernel stack. BusyBox sends two actual ping requests per interface.

Checks cover static ioctls and invalid masks, loopback and /32 local delivery, gateway/prefix/metric changes, eleven malformed ARP forms per interface, fifteen malformed IPv4/ICMP forms, three unanswered ARP attempts, quoted ICMP errors, broadcast policy, MTU bounds, kernel-generated echo/errors, and QMP link down/up. A lagging raw listener retains the oldest 32 of 48 datagrams; byte-quota tests retain three of four 20020-byte datagrams while another listener receives all four. Blocked send/receive tests change descriptors, vectors, and source pointers, then require the original bytes and metadata.

Cache tests resolve 129 distinct neighbors per adapter, retain the newest mapping, resolve the evicted oldest mapping again, and refresh a peer's changed MAC through an actual ARP request. Expiry tests use GDB to move one real reachable entry's expiration to the current tick, then require a new wire ARP request. No production test hooks are added.

The output-pressure test fills all 32 pending IP slots, requires `EAGAIN` and absent write readiness, and resumes a blocked 33rd sender after the peer answers ARP. The ARP reply ownership test separately injects `EAGAIN` at the exact x86-64 Ethernet function entry through GDB. A guest-acknowledged sequence of 96 ARP frames recycles more than a hardware RX ring while the original reply waits; after release the host requires its original 60 bytes. This tests protocol ownership under controlled backpressure. The [Ethernet suite](network.md#verification) separately fills the real driver TX capacity and observes actual completions.

Fault cases corrupt one actual virtio used-head identity at the RX validation boundary, require the bound raw socket's persistent error, and then exchange ICMP through the unaffected e1000 adapter. Full ABI/thread/compiler/signal/VFS/desktop/input, Ethernet, disk, ext2 root/data, delayed-flush, formatting, sanitizer, and corresponding-source checks remain required before integration.

Protocol references are [ARP](https://www.rfc-editor.org/rfc/rfc826), [IPv4](https://www.rfc-editor.org/rfc/rfc791), [ICMP](https://www.rfc-editor.org/rfc/rfc792), and [host requirements](https://www.rfc-editor.org/rfc/rfc1122). Linux contracts are compared with [raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html), [IP sockets](https://man7.org/linux/man-pages/man7/ip.7.html), [interface ioctls](https://man7.org/linux/man-pages/man7/netdevice.7.html), and the pinned [Linux 6.12 raw implementation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/raw.c) and [Internet address queries](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/af_inet.c). These references define the broader contracts; this initial slice does not claim complete conformance.
