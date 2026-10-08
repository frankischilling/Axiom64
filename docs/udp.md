# IPv4 UDP sockets

Ring 3 programs exchange UDP datagrams through `AF_INET/SOCK_DGRAM` with protocol zero or `IPPROTO_UDP`. The transport uses [IPv4 routes, ARP, and loopback](ipv4.md) and both [Ethernet adapters](network.md). TCP, IPv6 UDP, DHCP, DNS, and downloads remain required by the [networking roadmap](feature-roadmap.md).

## Ownership and binding

`kernel/net/udp/core.cpp` validates UDP lengths and checksums and constructs outgoing headers. Internet socket descriptions, ports, receive queues, and options live in `kernel/net/ipv4/socket.cpp`. The existing [I/O request layer](io.md) retains descriptions while operations block.

The shared Internet socket table holds 256 descriptions. Each UDP description has at most 32 queued datagrams and 65536 payload bytes. Buffer options double the supplied value and clamp it to 2048 through 65536 bytes. A full receive queue drops the new datagram and preserves older ones. A matching full socket does not generate a port-unreachable error.

`bind` supports wildcard and assigned local addresses. Conflicting wildcard/specific bindings return `EADDRINUSE` unless both descriptions enable `SO_REUSEADDR`. Unicast delivery selects the most specific local address, peer, port, and interface match, with the most recent binding breaking ties. Broadcast delivery gives each matching description an independent copy. `SO_REUSEPORT` is unsupported.

Automatic ports use a bounded search in 32768 through 60999. Ordinary close releases a port after the final descriptor or retained I/O owner ends; dup and fork share that owner. `connect(AF_UNSPEC)` clears the peer and releases an automatic port, including a port assigned by `bind` with port zero. An explicit nonzero bound port stays reserved. A specifically bound local address stays fixed; an automatically selected address returns to wildcard on disconnect.

Connected sockets filter input by peer address and nonzero peer port. A zero connected peer port remains a wildcard on input and makes `getpeername` return `ENOTCONN`. Named sends reject destination port zero. Named address zero selects loopback. These details have focused comparisons with the pinned Linux UDP path and native musl tests.

## Wire validation and output

Input requires an eight-byte header, declared length from eight through the validated IPv4 payload size, and a valid pseudo-header checksum when the checksum field is nonzero. The declared UDP length trims surplus IP payload. IPv4 zero checksums are accepted. Odd payload lengths use checksum padding without exposing that byte to the receiver.

Output selects the actual routed source address before calculating the pseudo-header checksum. A computed zero checksum is encoded as `0xffff`. The maximum unfragmented UDP payload is 65507 bytes on loopback; an Ethernet MTU of 1500 permits 1472 bytes. Larger packets return `EMSGSIZE`. Options and fragments remain rejected by the IPv4 layer.

Successful sends transfer owned bytes to the bounded IPv4 output queue. They do not acknowledge peer delivery. The send quota charges the IPv4 and UDP headers as well as the payload; output completion or failure returns that capacity. Broadcast output requires `SO_BROADCAST`. Missing ARP replies reach `EHOSTUNREACH` after the existing three-attempt policy.

A blocked send captures the selected description, destination address and port, vectors, and payload before waiting. Changes to those user buffers or reuse of the descriptor cannot redirect the attempt. Socket options, local configuration, and route selection remain live until acceptance. Closing a socket detaches its notification owner from already accepted output; the output retains its bytes until transmission or failure.

## Datagram I/O and errors

Read/write, vectors, send/receive, and message calls preserve datagram boundaries. Receive returns payload bytes and a `sockaddr_in` source address and port. `MSG_PEEK` retains the datagram; `MSG_TRUNC` returns its original payload length. A non-peek copy fault consumes the datagram. Zero descriptor reads retain queued data, while a zero-size socket receive consumes one datagram. A zero-length datagram is readable even though `FIONREAD` reports zero.

Nonblocking exhaustion returns `EAGAIN`. Poll and epoll report queued data, output capacity, and socket errors. Shutdown preserves queued and later input: read shutdown makes an empty blocking receive return zero, while an empty nonblocking receive returns `EAGAIN`. Write shutdown returns `EPIPE` without raising SIGPIPE. An unconnected shutdown sets its state while returning `ENOTCONN`, as in the tested Linux behavior.

A valid unicast datagram with no matching socket produces a rate-limited ICMP port-unreachable response quoting the original IP header and eight UDP bytes. Invalid UDP and broadcast input do not produce that response. Valid quoted errors match a connected local/remote tuple; malformed and unrelated quotes are ignored. Default unconnected sockets ignore quoted ICMP errors. A failed `SO_ERROR` copy retains the guest error; a successful copy clears it. A permanently failed bound adapter continues to report `EIO`, and the other adapter remains usable.

## Verification

```sh
make test-udp
python3 scripts/udp_test.py --firmware bios --transport modern
python3 scripts/udp_test.py --firmware uefi --transport legacy --fault
python3 scripts/udp_test.py --firmware uefi --transport modern --fault --debugger-delay 5
musl-gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static -pthread userspace/tests/net/udp.c -o build/udp-linux
./build/udp-linux
```

The matrix requires eight boots: BIOS/UEFI and modern/legacy virtio, each with normal traffic and a real virtio RX completion fault. The modern UEFI fault case adds five seconds of debugger setup delay to prove that host startup cannot consume guest ARP deadlines. Both adapters run together. The host peers construct and validate Ethernet/IP/UDP packets independently; guest socket operations execute in the kernel.

Normal cases require odd and maximum-MTU payloads, zero payloads, checksum-zero encoding, fourteen malformed forms per interface, source/peer filtering, client and server exchanges, loss/duplication/reordering, exact ICMP quotes, broadcast copies, byte quotas, and 48 proven broadcast arrivals retaining the oldest 32 on a lagging socket. A 33rd send blocks behind 32 unresolved outputs; the host then checks all original ports and payloads after descriptor and buffer replacement. QMP changes carrier state, and administrative state is tested separately.

Common cases cover bind conflicts, disconnect policy, reused ports, shutdown, truncation and copy faults, zero-size receives, a 65507-byte loopback payload, retained receive metadata, interruption/restart, fork ownership, and 128 resource-reuse cycles. Guest checks also prove the exact 2048-byte send quota, including 28 header bytes. CI runs the common cases on native Linux. Fault cases pause the guest while GDB installs the breakpoint, then require the actual corrupted completion, persistent device errors, and an exchange on the remaining adapter. Results are `build/udp-results.json`; serial and debugger evidence use `build/udp-*.log` and `build/udp-*.gdb`.

This slice does not implement multicast membership, fragmentation, UDP segmentation/offload, ancillary data, error queues, socket deadlines, message batches, Unix datagram data, or the complete Linux socket contract. Ports are sequential, and current tasks run as root; accounts, permissions, and secure randomness remain prerequisites for exposed services.

Protocol references are [UDP](https://www.rfc-editor.org/rfc/rfc768), [host requirements](https://www.rfc-editor.org/rfc/rfc1122), and [UDP surplus-area handling](https://www.rfc-editor.org/rfc/rfc9868). Linux comparisons use [Linux 6.12 UDP](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/udp.c), [Internet socket operations](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/af_inet.c), and [IP sysctls](https://github.com/torvalds/linux/blob/v6.12/Documentation/networking/ip-sysctl.rst). The tested contracts cover the behavior above; complete conformance remains planned.
