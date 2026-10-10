# IPv4 TCP implementation

The wire codec, sender policies and bounded connection engine are implemented under `kernel/net/tcp/`, with public interfaces under `kernel/include/net/tcp/`, tracked by [#118](https://github.com/frankischilling/Axiom64/issues/118). AF_INET/SOCK_STREAM creation and the guest TCP transport are still required in [#109](https://github.com/frankischilling/Axiom64/issues/109). This foundation is exercised by host tests and compiled into the kernel. Guest TCP, native socket comparisons and NIC wire acceptance remain prerequisites for the transport release.

## Packet and connection contract

`wire.hpp` decodes checksum-validated IPv4 TCP segments into borrowed payload views. It checks header bounds and option lengths, reads SYN MSS/window-scale options, skips unknown options and preserves the output object on malformed input. The encoder emits a minimal header and optional SYN MSS, with the IPv4 pseudo-header checksum. It supports overlapping input/output buffers. Window scaling is not offered, so peers retain unscaled 16-bit windows. Neither SACK nor timestamps are negotiated.

`connection.hpp` owns one endpoint's sequence space, application bytes, retransmission state and receive reassembly. The adapter must select a tuple, supply checksum-validated segments and a monotonic millisecond clock, and own the connection for its entire lifetime. It supplies the local MSS from the route MTU; the current upper bound is 1460. Peer MSS limits output, with a 536-byte default when no MSS option arrives. Ports and IPv4 addresses belong to the adapter.

The endpoint implements active/passive and simultaneous handshakes; established, half-close and simultaneous-close states; LAST-ACK; and 120-second TIME-WAIT. An exact-sequence reset aborts a synchronized connection, an in-window reset requests a challenge ACK, and an out-of-window reset is ignored. Future ACKs cannot release queued bytes. Old ACKs cannot update the sender window. Duplicate, overlapping and out-of-order receive bytes use bounded reassembly, with the first arrival owning overlapping bytes. A queued FIN waits for preceding data; bytes after accepted EOF are not delivered.

Each connection contains 32 KiB send storage, 32 KiB receive storage, a receive bitmap and a packet scratch buffer. Writes accept only available queue space. Limits can shrink without discarding already readable data. Peek reads preserve ownership. Reading reopens the advertised window. Read shutdown discards readable bytes while continuing to acknowledge the stream. Write shutdown sends FIN after preceding queued bytes have been transmitted.

`next()` produces a borrowed packet candidate. The adapter must copy it into an owned IPv4 output queue and then call `emitted()` immediately. A failed enqueue consumes no sequence numbers and starts no retransmission timer. Input, reads and writes invalidate the candidate. Listener/backlog ownership, tuple lookup, port allocation, file descriptions, syscall blocking, readiness and ICMP delivery belong to the kernel adapter and remain in #109.

## Sending and timers

`sender.hpp` supplies RTT/RTO and byte-based Reno congestion policies. The RTO starts at one second, filters ambiguous retransmission samples, updates RTT variation before the smoothed RTT, uses the kernel's 10 ms clock granularity and clamps to one through 60 seconds. Timer loss backs off exponentially and retransmits the oldest unacknowledged data. Repeated timer loss of that same sequence range holds the slow-start threshold. Fast retransmission has its own trigger and does not consume RTO backoff.

New data respects the peer window and congestion window. Three qualifying duplicate ACKs request fast retransmission. Slow start, byte-counted congestion avoidance, recovery and timer-loss restart follow the sender policy. SYN retransmission reduces the initial data window and retains the conservative data RTO. Default Nagle coalesces small writes while earlier data remains unacknowledged; the adapter can enable TCP_NODELAY. A 200 ms sender override bounds waiting on a small advertised window. Ring wrap uses packet scratch storage to preserve full segment sizing.

Zero-window probes run independently of RTO loss, with bounded one-through-60-second backoff. Probes can request reopening with queued data or FIN and do not consume a retransmission-failure budget. Window reopening schedules outstanding data promptly. The caller can set a finite user timeout for stalled queued data or FIN; zero disables that timeout. Handshakes expire after 60 seconds. Detaching an endpoint with unread data requests a reset; detached FIN-WAIT-2 expires after 60 seconds. TIME-WAIT retains the endpoint until its timer expires. The adapter must bound endpoint counts and reclaim storage after completion.

## Verification

Run `make test-tcp-wire test-tcp-sender test-tcp-connection`. All three use ASAN/UBSAN and leak checking against the production modules.

- The wire test checks independent fixed packet/checksum fixtures, every single-bit corruption of a fixture, malformed headers/options, overlapping output, sequence wrap, window/reset decisions and 50,000 checksum-repaired mutations.
- The sender test checks RTT update order, Karn filtering, SYN fallback, repeated RTOs, congestion growth/recovery and arithmetic bounds across 50,000 events.
- The connection test checks output enqueue failure, handshake/refusal/simultaneous open, overlap/gaps/queued FIN, stale/future ACK behavior, reset validation, fast retransmission/RTO, Nagle/SWS timing, finite deadlines, zero-window reopening, shutdown and close ownership. Its deterministic 300,000-byte transfer crosses the production codec while losing, duplicating and reordering packets and wrapping sequence numbers. Queue bounds and exact received bytes are checked throughout.

CI retains the host log in the `tcp-policy` artifact and continues to run the complete existing native and VM suite. The corresponding source bundle includes the modules, tests, recipes and this document. Socket integration must add static/dynamic musl and native Linux clients, retained-I/O/error/readiness checks, listener pressure, and independent NIC wire peers across both firmware modes, adapters and virtio transports before #109 closes.

## Sources and remaining work

The wire/state contract follows [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), retransmission timing follows [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html), and sender congestion control follows [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html). Linux behavior is checked against [`net/ipv4/tcp_input.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_input.c), [`tcp_output.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_output.c), [`tcp_timer.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_timer.c) and the socket implementation at that pinned revision.

Linux socket integration, actual controlled-peer guest acceptance and complete TCP options remain required. IPv6 transport, urgent/OOB handling, DNS TCP fallback, TLS, ISN entropy integration and SMP are separate outstanding work. The VM operating system and required workloads come first; HP-specific development follows the readiness review in [#74](https://github.com/frankischilling/Axiom64/issues/74).
