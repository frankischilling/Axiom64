# Ethernet and packet sockets

The kernel has a shared Ethernet interface for PCI virtio-net and QEMU's Intel 82540EM e1000 model (`8086:100e`). Ring 3 programs can discover interfaces and exchange raw Ethernet frames through Linux `AF_PACKET`/`SOCK_RAW` sockets. The [initial IPv4 path](ipv4.md) adds static addresses, routes, ARP, and raw ICMP/ping. DHCP, DNS, TCP/UDP, downloads, and complete IPv4/IPv6 behavior remain in their full [protocol scopes](feature-roadmap.md). Both adapters are required for the first networking release.

## Devices and ownership

Up to eight interfaces receive stable indices within a boot and names `eth0` through `eth7` in PCI discovery order. Each exposes its MAC, MTU, administrative state, carrier, and bounded receive/transmit/drop/error counters through `NetInfo`. Interfaces start administratively down. Setting `IFF_UP` never changes physical carrier.

Virtio uses separate receive and transmit split queues through the [shared PCI transport](virtio.md). Modern and legacy transports negotiate only MAC, status, and MTU device features, plus the transport's modern-version bit. MAC is required and validated. Status is read when offered; absent status defaults to carrier up. Offered MTU bounds the buffer allocation and configurable MTU; omission selects 1500. Mergeable buffers, offloads, multiqueue, and interrupt delivery are not negotiated. Modern headers occupy 12 bytes and legacy headers 10 bytes. QEMU can leave the modern buffer-count field zero when mergeable buffers are disabled; the receive path accepts zero or one buffer and rejects a multi-buffer payload.

Modern RX queues select up to 1024 descriptors; legacy queues retain the device-reported size. QEMU 8.2.2 offers RX sizes 256, 512, or 1024 and fixes TX at 256. Each queue uses at most 64 independently owned contiguous payload buffers. Transmission copies the whole frame into an available driver buffer and reclaims it after the matching completion. Receive validates the completion and header, copies accepted frames into listener queues, then recycles the driver buffer. Malformed identity stops the adapter; malformed payload length is dropped.

The e1000 adapter validates the PCI class and memory BAR, resets the controller, reads its assigned MAC, and uses separate 64-entry legacy descriptor rings with 2048-byte buffers. TX leaves one descriptor unused, copies a whole frame, and reclaims only descriptors with completion writeback. RX requires a complete, error-free frame and bounds its length before copying. Broadcast and multicast receive are enabled; unsupported fragments are dropped. MTU is limited to 1500. This implementation claims QEMU's 82540EM model; e1000e and other Intel/Realtek devices remain planned.

Network polling runs with serialized callers on one CPU, in syscall attempts and the scheduler's blocked-task loop. Receive and completion continue while every user task waits. MSI/MSI-X and PCI INTx remain masked, and both adapters suppress or mask device interrupts. Failed adapters retain their DMA allocations and ownership records; virtio acknowledges reset before any attach cleanup frees storage. e1000 pages remain allocated for the controller's lifetime. Shutdown stops both adapters before filesystem finalization. SMP, interrupt-driven completion, reset recovery, and hot removal remain planned.

## Linux socket contract

`socket(AF_PACKET, SOCK_RAW, htons(protocol))` supports `SOCK_NONBLOCK` and `SOCK_CLOEXEC`. `bind` selects an interface index and network-order protocol; index zero listens across interfaces. Protocol zero receives no packets, and `ETH_P_ALL` receives every supported Ethernet protocol. Binding protocol zero preserves an existing nonzero protocol, following Linux's bind behavior.

`read`/`write`, `readv`/`writev`, `sendto`/`recvfrom`, and `sendmsg`/`recvmsg` operate on whole frames. Raw sends preserve the caller's Ethernet header. The optional send address selects an interface. Input vectors, address metadata, and the complete TX payload are captured before a blocking attempt; resumption uses the retained open description even if another thread closes and reuses the descriptor. `dup`, fork, and last-close lifetime follow the shared Handle.

Receive supports `MSG_DONTWAIT`, `MSG_PEEK`, and `MSG_TRUNC`. Truncated receives consume one frame unless peeking; `MSG_TRUNC` returns its wire length, and `recvmsg` reports the truncation flag. Source `sockaddr_ll` contains the interface, protocol, Ethernet hardware type, packet type, and source MAC. Each listener owns its copy: at most 32 frames and 65536 payload bytes. A full listener drops new frames without affecting another listener. `PACKET_STATISTICS` reports and resets delivered-plus-dropped packet and drop counts. `PACKET_IGNORE_OUTGOING` disables locally transmitted frames for that listener; the originating socket does not receive its own send.

`poll` and epoll report receive availability and TX readiness. A permanently failed bound adapter reports `POLLERR` and I/O returns `EIO`; carrier or administrative down returns `ENETDOWN` on transmission. Nonblocking exhaustion returns `EAGAIN`. `FIONREAD` reports the next frame length. Interface ioctls support name/index, MAC, MTU, flags, and [IPv4 address controls](ipv4.md#configuration-and-routing). `SIOCGIFCONF` lists configured IPv4 interfaces and the fixed loopback address.

`getsockname`, socket type/domain/protocol, and the fixed buffer-size queries are supported. Datagram packet sockets, connect/listen/accept/shutdown, socket deadlines, ancillary data, packet mmap rings, BPF, memberships, advanced interface flags, and other unimplemented options return explicit errors. Current tasks run as root; capability-based raw-socket authorization is part of the planned accounts and permissions work. Exposed services still require that work and secure randomness.

## Verification

```sh
make test-network
python3 scripts/network_test.py --firmware both --models virtio e1000
python3 scripts/network_test.py --firmware both --transport legacy --queue 512 --wrap
python3 scripts/network_test.py --firmware both --models virtio --fault id
python3 scripts/network_test.py --firmware both --models e1000 --fault length
python3 scripts/network_test.py --firmware both --models e1000 --pressure
python3 scripts/network_test.py --firmware both --models virtio --no-status
python3 scripts/network_test.py --firmware both --models virtio e1000 --mtu 9000
```

The complete matrix runs 46 dedicated boots: 12 mixed-adapter firmware/transport/queue-size cases, four eight-interface boots, four rollover boots, ten malformed-completion boots, six TX pressure boots, four absent-status boots, four mixed-adapter jumbo-MTU boots, and two explicitly offered 1500-MTU boots. GDB is a host test dependency. Results accumulate in `build/network-results.json`; a failed case stops the matrix and retains its evidence.

The harness gives each NIC an isolated loopback TCP peer. It checks the QEMU framing prefix, interface-specific MACs, experimental EtherType, sequence, length, and every payload byte before returning a reply. Firmware-generated traffic is counted separately. Guest checks cover address metadata, vectors, peek/truncation, filters, nonblocking behavior, poll/epoll while idle, duplicate/fork lifetime, and blocked `recvmsg` after descriptor and metadata reuse. A lagging listener retains 32 of 48 replies and records exactly 16 drops while the active listener receives all replies. QMP controls physical carrier down/up independently of the administrator flag.

The wrap phase exchanges 65,621 host-validated frames per NIC. Fault cases use GDB to alter one actual RX completion at its validation boundary in a dedicated VM: oversized virtio/e1000 lengths are dropped before valid traffic resumes; an invalid virtio head quarantines the adapter and wakes the socket with an error. These tests alter the emulated device's completion memory, without adding production test hooks.

TX pressure tests defer driver polling through GDB while the real device transmits and writes completions. They fill all 64 virtio buffers or 63 e1000 descriptors, verify `EAGAIN` and absent write readiness, then resume polling and require epoll to wake an idle sender. The test leaves device-written completions intact and compares every transmitted byte after the caller overwrites its original buffer. This covers delayed completion observation; it does not claim a fault-injected physical DMA engine stall.

Optional-feature tests validate the negotiated bits, carrier fallback without STATUS, and MTU bounds. A 9000-byte offered virtio MTU sends and receives a 9014-byte frame alongside e1000's 1500-byte limit. Failed receive copies retain a queued frame; zero-length descriptor reads, zero-length receives, and peek/truncation behavior are checked separately. Evidence uses `build/network-*`; full ABI/thread/compiler/signal/VFS/desktop/input, storage, ext2, disk-root, formatting, sanitizer, and source-bundle checks remain required before integration.

The contracts follow [virtio 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html), [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html), [Linux interface ioctls](https://man7.org/linux/man-pages/man7/netdevice.7.html), and [QEMU's e1000 model](https://github.com/qemu/qemu/blob/v8.2.2/hw/net/e1000.c). The controlled peer uses [QEMU's socket framing](https://github.com/qemu/qemu/blob/v8.2.2/net/socket.c).
