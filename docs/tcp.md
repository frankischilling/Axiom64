# IPv4 TCP implementation

The wire codec, sender policies and bounded connection engine are implemented under `kernel/net/tcp/`, with public interfaces under `kernel/include/net/tcp/`. The Linux AF_INET/SOCK_STREAM adapter adds ordinary active/passive connections and native host interoperability in Linux TCP socket integration. Retained MSG_WAITALL progress and compact TIME-WAIT storage are implemented in [retained receive progress](io.md). Full retained-call, reclamation and controlled NIC fault acceptance remain required in TCP reliability and the complete transport checklist in TCP sockets. This integration does not complete the transport or VM operating-system milestones.

## Linux socket integration

`socket.cpp` owns tuple lookup, listener children, connection allocation, clocks and packet submission. The IPv4 socket module owns the shared bounded pool, port binding and file-description attachment. Each TCP connection is constructed in heap storage; no large endpoint temporary is placed on the kernel stack. A blocked call retains the existing file description through the common I/O request mechanism. Transmission advances sequence/timer state only after the IPv4 queue owns the complete encoded packet.

Supported calls include default/IPPROTO_TCP stream creation with nonblocking and close-on-exec flags, bind, listen, accept/accept4, connect, getsockname/getpeername, read/write/readv/writev, send/recv/sendmsg/recvmsg, peek/MSG_WAITALL, shutdown and poll/epoll readiness. The tested subset includes explicit loopback and wildcard bindings, TCP/UDP port separation, accepted descriptor flags, refusal/SO_ERROR clearing, vector reads crossing the 4096-byte copy buffer, retained dup descriptions and EOF/EPOLLRDHUP. TCP receives ignore source-address output and return zero address length, as native Linux does. Unsupported message flags and additional contracts remain documented below.

`SO_REUSEADDR` allows overlapping bound-only TCP sockets when both owners enable
it. An active listener keeps its overlapping address and port exclusive. First
listen rechecks the current reuse flags on all overlapping owners; an existing
listener can still update its backlog after changing those flags. Failed first
listen retains the binding for a later retry. A failed bind can be retried after
the conflicting owner closes. The common native and guest socket program checks
48 wildcard/loopback binding and flag-transition cases, including listener
handover and backlog updates. Broader Linux reuse policies remain required.

Active sockets keep pending connect completion separate from the transport handshake. After a nonblocking handshake, a repeated connect completes the pending socket state and returns zero once; later calls return EISCONN. Dup descriptions share this state. An existing pending handshake returns EALREADY to nonblocking calls, while a blocking call can keep waiting through its retained description and imported destination. Finite waits retain their initial EINPROGRESS or repeated EALREADY result. Caught signals interrupt finite waits even with SA_RESTART; an infinite restarted wait can complete the existing handshake. [connect completion](io.md) records this completion/retry subset.

A failed pending connect consumes the socket error and returns to an unconnected state. If SO_ERROR already consumed the refusal, completion returns ECONNABORTED. The adapter detaches old owned-output callbacks, releases the old connection storage, clears peer/shutdown/error state and constructs a fresh engine for a later attempt. Socket options and explicit address/nonzero-port bindings survive. An automatically assigned port loses its binding owner after the closed attempt's pending output has been copied; getsockname still reports the last source port, matching Linux's separate bind-owner and reported-port fields. Completion clears an automatically chosen source address. These state and binding rules follow pinned [__inet_stream_connect](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/af_inet.c), [tcp_disconnect/tcp_set_state](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp.c) and [inet_put_port](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/inet_hashtables.c).

TCP_NODELAY and TCP_USER_TIMEOUT can be set/read; both default to zero. SO_RCVTIMEO/SO_SNDTIMEO use the common finite socket deadline mechanism. Socket buffers have fixed bounded storage rather than Linux autotuning. Additional TCP options remain unsupported.

TCP_MAXSEG accepts zero or 88 through 32767. Fresh and listening sockets report the configured positive limit, or 536 before a limit is configured. Connected sockets report the effective sending MSS, including peer negotiation and validated path-MTU reductions. Axiom64 retains its 1460-byte upper bound for transmitted segments. Setting a limit after connection preserves the current negotiated limit and queued bytes; the setting applies to a later connection. An AF_UNSPEC disconnect clears the configured limit and retains the last effective MSS for queries until the next connection computes its path limit.

`connect` with `AF_UNSPEC` disconnects the current stream and makes its file
description reusable. A two-byte family is sufficient; bad lengths and inaccessible
addresses return their Linux errors. Dup aliases share the reset, socket options
and explicit binding. Completed TIME-WAIT tuples keep their compact guards when
the description is reused. Immediate reuse of a completed identical tuple is still
rejected; Linux permits the measured same-description case. Reset diagnostics remain available through `SO_ERROR`
until consumed, and a new admitted connection clears old diagnostics.

Each retained stream call captures a connection generation. Explicit disconnect
changes that generation, so an old read, write or connect cannot use the successor
stream. An interrupted retained read returns its completed prefix, or `EPIPE` when
it has no progress, without consuming the new stream's bytes or diagnostic state.
The native comparison checks both outcomes with vectored `MSG_WAITALL`, immediate
reconnect, exact successor bytes and shared socket errors. Listener accept behavior
uses its listener/queue state separately.

A blocked connect through an alias returns `EPIPE` after explicit disconnect,
without generating `SIGPIPE` or consuming a successor's error. Disconnect wakes
an old accept with `EINVAL` when the description stays unconnected. If the same
description listens again before that accept runs, the call may instead accept
one new child. The comparison covers both native race outcomes, exact new-stream
bytes, accepted descriptor flags and release of the reserved descriptor slot.

A cancelled write with no progress consumes its old reset diagnostic while the
description has no successor stream. A partial write returns its completed prefix
and leaves the diagnostic available. With a successor, the old call returns its
prefix or `EPIPE` without consuming the successor's error or copying more payload.
`writev` generates `SIGPIPE` for an unconsumed `EPIPE`; `sendmsg` with `MSG_NOSIGNAL`
suppresses it. Regression cases include an inaccessible payload behind a full old
send queue, so cancellation must complete before any user-buffer access.

TCP keeps buffered bytes through a temporary administrative interface outage
or loss of a connected or explicit host route. An `ENETDOWN` or `ENETUNREACH`
enqueue rejection leaves its sequence pending. Local queue and route failures
schedule a 200-millisecond retry without consuming sequence space or backing off
the retransmission timer. Delivery and configured user deadlines still bound
the wait, including data that has never reached the IPv4 queue. Fresh connects
continue to fail immediately when no route exists. If IPv4 already
owns a packet copy, discarding that copy returns its queue credit while TCP keeps
the unacknowledged bytes for retransmission. This includes `ENOBUFS` when a ready
IPv4 copy expires under local transmit backpressure. Device failure remains a separate
hard error. This follows the retained transmit queue in pinned
[Linux TCP output](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_output.c).

`sudo -n make test-tcp-recovery-native` and `make test-tcp-recovery-sockets`
compare recovery on both interfaces, with exact payloads and live companion
traffic on the other interface. The queued-output cases confirm pending bytes
before lowering the interface: native Linux uses a private egress delay queue;
the guest fixture holds the Ethernet transmit boundary at `EAGAIN`. Neither
fixture changes TCP state or clocks. Debugger observations establish ownership
and recovery; retransmission timing is checked by the separate wire profiles.
Native `SO_ERROR` may expose advisory `ENETUNREACH` during an outage while the
stream remains usable. A second hold on each NIC keeps the interface up for at
least 4500 milliseconds, confirms actual guest copy expiry and then recovers the
stream with live companion traffic. Native Linux uses a ten-second private egress
delay for this case. The application retains its full wait; the native and guest
fixtures release output after that observation. The program's overall alarm is
60 seconds for the additional two waits; each VM profile keeps its 150-second
limit. TCP's default, configured, retransmission and application deadlines remain
unchanged. Additional cases withdraw the connected route with a netmask change
and delete an explicit on-link host route on each NIC. Each confirms a fresh
connect fails with `ENETUNREACH`, retains 512 undelivered bytes, exchanges exact
companion traffic and recovers after restoration. Physical-carrier cases keep the
client interfaces administratively up. Native Linux lowers the selected veth port
behind an up bridge observer; the guest uses one shared QMP monitor to change each
real adapter's link. A complete companion echo acknowledges actual carrier loss
before the application submits its 512 selected bytes. Those bytes remain
undelivered until restoration, with no socket error. Each complete stream carries
6224 data bytes and four control bytes. Wider route policies, longer outages and
permanent device failure still require their wider acceptance cases.

`scripts/tcp_recovery_capture.py` independently reconstructs both streams, the
Q/H control positions, every ACK and both closes. It checks actual physical-link
operations, administrative state, complete companion progress and carrier-byte
ordering, alongside the native queue backlog or guest held/released boundary logs
and the frozen source,
compiled product and native library fingerprints. The CLI requires the complete
three-linkage native or eight-profile guest cohort. Its damaged-evidence test
requires rejection of 513 altered packet, control, queue, expiry, route, carrier, result,
source and cohort cases, including shortened waits, absent physical expiry evidence,
false fresh-connect results and missing or reordered route restoration. Native
capture receipts also establish the order of physical-link operations and packets.
The test bridge disables [multicast snooping](https://docs.kernel.org/networking/bridge.html#bridge-netlink-attributes)
before it is brought up, preventing
its own IGMP reports from entering this isolated TCP workload. Captures remain
unfiltered and the reader still rejects unexpected IPv4 traffic.

Explicit disconnect advances the description's next sequence beyond all old
queued bytes and the largest advertised peer window. Later connections on that
description carry the advanced sequence across destination changes, so an
intervening connection cannot erase protection for an earlier tuple. The advance
accounts for a queued FIN, sequence wrap and the nonzero restart value. New
descriptions use the keyed initial-sequence generator. This does not shorten
TIME-WAIT, retransmission or application deadlines.

`sudo -n make test-tcp-reconnect-native` and `make test-tcp-reconnect-sockets` exercise
both NICs with six cases each. Aborted streams reuse the same bound description
and tuple with 32768 independently generated bytes in each phase. Completed streams
retain the measured wire-path tuple guard and reconnect to an independent destination
with the same source port. Two peer windows, wrapped peer sequences, exact replies,
owned resets and fully acknowledged FINs are checked from original packets by
`scripts/tcp_reconnect_capture.py`.

An additional three-open case transfers 262144 bytes to one destination, briefly
connects to a second destination, then returns to the first on the same bound
description. Independent checks require each restart to exclude its predecessor's
full sequence window and the final open to exclude the original stream. Exact
bytes, both resets, the final close and retained source address are checked.

The queued-copy case keeps 512 old bytes pending while `AF_UNSPEC` disconnects
the description and a successor opens on its exact original tuple. Native Linux
retains the old copies in a ten-second egress queue while a classifier change
allows future packets through. The guest observer holds the actual old transmit
copy until its four-second expiry and verifies that its callback owner is empty.
Each NIC waits at least eleven seconds, transfers exact successor bytes and keeps
the other NIC active. Original packets, queue commands and fingerprinted observer
traces establish ownership; debugger observations do not establish transport
timing. Guest profiles use two isolated VMs concurrently after both linkage images
are built. Broader Linux
reuse policies remain part of complete transport acceptance.

Initial sequences use a 32-byte secret obtained only from the ready kernel random source, a domain-separated HMAC-BLAKE2s of the IPv4/port tuple and a monotonic sequence clock. Allocation/output retries do not substitute a predictable fallback. The derivation has independent standard HMAC fixtures. This integration does not establish the full entropy, saved-state, adversarial ISN or SMP acceptance in randomness/TCP sockets.

The shared Internet pool contains at most 256 sockets, with at most 32 unaccepted children per listener and 32 KiB send/receive storage per connection. Each active or passive connection reserves a slot in a separate 1024-record TIME-WAIT table before its handshake. After TCP submits its final packets, a detached endpoint transfers completed state to its reserved record and releases its application buffers and general socket slot. IPv4 owns the final packet copies independently. Resets, failed allocation and failed attempts release unused reservations.

The table bounds reservations and completed records together. A full table rejects new TCP state with ENOBUFS, while a listener can leave a SYN unadmitted until capacity returns. A finite connect waiting for listener capacity retains its normal EINPROGRESS timeout result. Completed sequence state is never evicted to admit another connection. UDP and other Internet sockets keep their shared pool available.

Each compact record is at most 64 bytes, including completed sequence state, tuple, binding, TTL and deadline. Expiry releases only elapsed records; duplicate FINs restart the 120-second timer. Completed tuples remain protected against premature reconnect and still own conflicting bound ports. Ephemeral allocation includes both live sockets and compact owners. The pressure regression reaches the admission limit, preserves live companions and 32 fresh UDP endpoints, observes the entire 120-second interval and repeats the workload after expiry. The complete transport checklist remains required for full TCP reliability.

MSG_WAITALL retains imported vector metadata and a cursor through the original file description. Delayed chunks append to the remaining user buffers; peek advances a saved offset without consuming bytes. Nonblocking calls return an available prefix, and EOF, a finite deadline or a caught signal returns already transferred bytes. Partial progress prevents SA_RESTART from replaying that prefix. An unavailable peek offset waits for more bytes rather than appearing as EOF.

Blocking TCP write/writev/send/sendmsg calls retain queued-byte progress and resume at the remaining cursor when the peer makes room. A finite send deadline or caught signal returns the completed prefix, and partial progress prevents SA_RESTART from replaying bytes. O_NONBLOCK is captured at entry for this retained progress: changes through an alias affect later calls. Initially nonblocking descriptions and MSG_DONTWAIT return available prefixes immediately. The original description and imported vectors survive concurrent close/reuse or dup2 replacement; another stream cannot receive those bytes. [Blocking I/O](io.md) describes this send progress; complete TCP lifetime and fault acceptance remain required.

TCP user copies observe stream state before checking page mappings. Empty receives and full send queues keep their finite wait or immediate EAGAIN result even with a range-valid unmapped buffer. Receives peek into owned kernel scratch storage, copy the available bytes to the user page, then consume only after the copy succeeds. First copy faults preserve queued data; valid short reads can use a mapped prefix despite an unmapped unused tail. Writes check errors/capacity before copying a page into the owned stream queue. Later copy faults preserve already committed prefixes, and queued bytes survive source unmapping. Copy boundaries can affect the returned prefix length, so tests verify returned counts, exact remaining queue bytes and delivered data. [TCP copy and wait behavior](io.md) covers this subset. The peek/copy/consume sequence uses the current single-CPU discipline; SMP synchronization remains required.

TCP accepts hold a reserved output descriptor while waiting. An uninterrupted call keeps its original listener through concurrent close/reuse or dup2 replacement, and a different replacement listener keeps its own queued children. Caught signals release the attempt's reservation before the handler; SA_RESTART without a finite deadline re-enters through a fresh descriptor lookup, while an interrupted finite attempt returns EINTR. Full-table errors precede waiting and preserve queued children. [Blocking I/O](io.md) describes these accept rules; remaining backlog/child pressure and wider connect/send/receive contracts remain required for full TCP reliability.

## Packet and connection contract

`wire.hpp` decodes checksum-validated IPv4 TCP segments into borrowed payload views. It checks header bounds and option lengths, reads SYN MSS/window-scale options, skips unknown options and preserves the output object on malformed input. The encoder emits a minimal header and optional SYN MSS, with the IPv4 pseudo-header checksum. It supports overlapping input/output buffers. Window scaling is not offered, so peers retain unscaled 16-bit windows. Neither SACK nor timestamps are negotiated.

`connection.hpp` owns one endpoint's sequence space, application bytes, retransmission state and receive reassembly. The adapter must select a tuple, supply checksum-validated segments and a monotonic millisecond clock, and own the connection for its entire lifetime. It supplies the local MSS from the route MTU; the current upper bound is 1460. Peer MSS limits output, with a 536-byte default when no MSS option arrives. Ports and IPv4 addresses belong to the adapter.

The endpoint implements active/passive and simultaneous handshakes; established, half-close and simultaneous-close states; LAST-ACK; and 120-second TIME-WAIT. An exact-sequence reset aborts a synchronized connection, an in-window reset requests a challenge ACK, and an out-of-window reset is ignored. Future ACKs cannot release queued bytes. Old ACKs cannot update the sender window. Duplicate, overlapping and out-of-order receive bytes use bounded reassembly, with the first arrival owning overlapping bytes. A queued FIN waits for preceding data; bytes after accepted EOF are not delivered.

Each connection contains 32 KiB send storage, 32 KiB receive storage, a receive bitmap and a packet scratch buffer. Writes accept only available queue space. Limits can shrink without discarding already readable data. Peek reads preserve ownership. Reading reopens the advertised window. Read shutdown discards readable bytes while continuing to acknowledge the stream. Write shutdown sends FIN after preceding queued bytes have been transmitted.

`next()` produces a borrowed packet candidate. The adapter must copy it into an owned IPv4 output queue and then call `emitted()` immediately. For a temporary enqueue rejection it calls `output_blocked()` instead. Rejection consumes no sequence numbers and starts no retransmission timer; the engine schedules its local retry and starts bounded delivery waiting for data, FIN or a probe. Inspecting an offer without reporting an actual attempt does not start that period. Pure ACK rejection creates no delivery deadline. Input, reads and writes invalidate the candidate. Listener/backlog ownership, tuple lookup, port allocation, file descriptions, syscall blocking, readiness and ICMP delivery belong to the kernel adapter; full fault/lifetime acceptance remains in TCP sockets/TCP reliability.

## Sending and timers

`sender.hpp` supplies RTT/RTO and byte-based Reno congestion policies. The RTO starts at one second, filters ambiguous retransmission samples, updates RTT variation before the smoothed RTT, uses the kernel's 10 ms clock granularity and clamps to one through 60 seconds. Timer loss backs off exponentially and retransmits the oldest unacknowledged data. Repeated timer loss of that same sequence range holds the slow-start threshold. Fast retransmission has its own trigger and does not consume RTO backoff.

New data respects the peer window and congestion window. Three qualifying duplicate ACKs request fast retransmission. Slow start, byte-counted congestion avoidance, recovery and timer-loss restart follow the sender policy. SYN retransmission reduces the initial data window and retains the conservative data RTO. Default Nagle coalesces small writes while earlier data remains unacknowledged; the adapter can enable TCP_NODELAY. A 200 ms sender override bounds waiting on a small advertised window. Ring wrap uses packet scratch storage to preserve full segment sizing.

Zero-window probes run independently of RTO loss, with bounded one-through-60-second backoff. A newly closed window starts a fresh period using the current RTO; repeated zero-window ACKs preserve its backoff. Probes can request reopening with queued data or FIN. Window reopening schedules outstanding data promptly. With TCP_USER_TIMEOUT at zero, unanswered data, FIN and probes expire after 924600 ms without accepted progress or a responsive zero-window answer. A validated stopped receiver can keep answering probes indefinitely; reopening starts a fresh delivery period. Open-window duplicate ACKs, invalid control segments and failed output submissions cannot restart the default period. A positive configured timeout remains authoritative, including values longer than the default. [Full lifetime acceptance](tcp-default-lifetime.md) describes the separate real observations and supported limits. Handshakes expire after 60 seconds. Detaching an endpoint with unread data requests a reset; detached FIN-WAIT-2 expires after 60 seconds. TIME-WAIT retains completed sequence state until its timer expires. Last close immediately reclaims an already closed endpoint when it has no pending output; a reset still awaiting output ownership uses the ordinary poll path.

## Verification

Run `make test-tcp-wire test-tcp-sender test-tcp-connection test-tcp-isn test-tcp-time-wait`. All five use ASAN/UBSAN and leak checking against the production modules.

- The wire test checks independent fixed packet/checksum fixtures, every single-bit corruption of a fixture, malformed headers/options, overlapping output, sequence wrap, window/reset decisions and 50,000 checksum-repaired mutations.
- The sender test checks RTT update order, Karn filtering, SYN fallback, repeated RTOs, congestion growth/recovery and arithmetic bounds across 50,000 events.
- The connection test checks output enqueue failure, handshake/refusal/simultaneous open, overlap/gaps/queued FIN, stale/future ACK behavior, reset validation, fast retransmission/RTO, Nagle/SWS timing, finite deadlines, zero-window reopening, shutdown and close ownership. Eighteen local-output cases check bounded unsent data/FIN, repeated rejection, unchanged RTO and sequence ownership, exact recovery, independent streams, pure ACKs and backward/saturating clocks. Reopening a window or later accepting a waiting FIN cannot renew its configured deadline. Its deterministic 300,000-byte transfer crosses the production codec while losing, duplicating and reordering packets and wrapping sequence numbers. Queue bounds and exact received bytes are checked throughout.

- The compact completed-state test checks duplicate FINs, exact/in-window/out-of-window resets, old/future ACKs, sequence wrap, zero windows, malformed input and expiry/saturating timer bounds.

`make test-tcp-native` runs the common socket/loopback program with native glibc, static musl and dynamic musl. It checks delayed/peek/nonblocking MSG_WAITALL, partial signal and deadline results, retained vector reads through concurrent close/reuse and dup2 replacement, and 300 successful half-close cycles. The retained-read cases wait until the prefix has actually been consumed before replacing the descriptor; unrelated replacement bytes and changed vector metadata must remain untouched. Peer EOF checks verify final owner release. Accept tests also cover full tables, pending slot ownership under pressure, raw dup2/dup3 conflicts, private fork tables, timeout cleanup, listener close/replacement, caught-signal restart, finite interruption, successful exec and fatal group teardown. The exec marker verifies the copied table can allocate at the former reserved slot; a later refused connection detects a leaked listener owner. Raw syscall comparison is intentional: musl retries EBUSY inside its dup wrapper. Send tests hold the receive window closed to prove a writev/sendmsg is blocked after positive progress, then change alias flags, replace the descriptor and mutate vector metadata before draining exactly 262149 original bytes through EOF. Finite send/write/writev deadlines and directed signals with SA_RESTART on/off return prefixes whose bytes remain intact after the source is overwritten and freed. Separate O_NONBLOCK/MSG_DONTWAIT cases verify immediate partial completion. Guarded-buffer tests cover all four scalar/vector read and write forms, eight unavailable receive cases, eight genuinely full-queue send cases, finite and nonblocking waits, first/peek copy faults, short mapped prefixes with an unmapped tail, remaining queued bytes and exact send ownership through EOF after unmapping. Connect tests cover first nonblocking completion through dup descriptions, blocking completion, already-connected errors, four refusal/consumed-error/binding cases, option preservation and successful reuse. Real listener pressure retains SYN handshakes for two descriptor-replacement tests with an unmapped imported destination, three finite/infinite signal/restart tests, and first/repeated finite-deadline results. Exact accepted-child counts, untouched replacements and final EOF verify ownership. `make test-tcp-sockets` runs both musl builds in actual BIOS/UEFI loopback guests. `make test-tcp-native-wire` runs all eight linkage/firmware/virtio transport combinations with virtio-net and e1000 together. Native Linux sockets act as both client and server through QEMU's isolated user-network bridge. Every direction transfers 262144 independently generated bytes; each guest transfers one MiB per NIC. Native endpoints check exact bytes and EOF, while the independent capture parser validates headers/checksums, MSS limits, sequence ownership, all bytes and acknowledged FINs. This bridge coverage does not replace controlled fault peers.

Native listeners are bound before boot. Their accept workers start when the guest enters the corresponding NIC phase, after the common socket tests; the existing twenty-second accept/data deadlines measure that phase. The overall guest deadline still bounds startup and the complete run.

The user-network bridge can emit incoming resets in response to later window-update ACKs after complete close. Capture acceptance permits only exact resets after both FINs are already acknowledged and reports their count. Outgoing resets, resets during a transfer, wrong data and premature EOF still fail. `python3 scripts/tests/tcp_capture_test.py` rechecks all 16 actual NIC captures and deliberately damages six real fixtures: checksum corruption, checksum-repaired wrong bytes, malformed MSS, premature FIN, an early reset and truncation. Every damaged fixture must fail for its intended reason.

CI retains the host log in `tcp-policy`, native/guest JSON results and full PCAPs in `axiom64-evidence-tcp`, and the boot images in `axiom64-tcp-fixtures`. The corresponding source bundle includes the modules, tests, recipes and this document. Every earlier native and VM gate remains enabled. The full TCP sockets release still requires the remaining connect/accept/send and receive lifetime contracts, broader reclamation/pressure cycles and actual controlled NIC reliability/fault evidence for full TCP reliability.

## Sources and remaining work

Native failed-connect comparisons select a known unused automatic source port with
Linux [IP_LOCAL_PORT_RANGE](https://man7.org/linux/man-pages/man2/IP_LOCAL_PORT_RANGE.2const.html), then restore the default range before retrying. Linux
can otherwise share an automatically selected port with an unrelated TIME_WAIT
tuple, which makes an exclusive bind fail even after the refused socket releases
its ownership. The original release, explicit-binding, option and same-description
retry assertions remain. `sudo -n python3 scripts/tests/tcp_auto_port_test.py`
constructs that actual TIME_WAIT collision in a private namespace, checks an unused
control, and runs all four ownership/retry cases with all three native libc variants.
It preserves the parent namespace. This native fixture requires Linux 6.3 or later.

[Per-connection challenge ACK intervals](tcp-challenge-ack.md) bound rejected control
replies to one per 500 ms while preserving valid data ACKs, exact resets and independent
connections. Its concurrent native/VM packet profile observes mixed bursts, full silence
and exact recovery separately from the earlier five fault profiles.

The wire/state contract follows [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), retransmission timing follows [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html), and sender congestion control follows [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html). Linux behavior is checked against [`tcp.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp.c), [`net/ipv4/tcp_input.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_input.c), [`tcp_output.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_output.c), [`tcp_timer.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_timer.c), [`tcp_minisocks.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_minisocks.c) and [`net/socket.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/socket.c) and [`net/core/datagram.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/core/datagram.c) at that pinned revision. The compact close policy preserves this engine's conservative completed-state behavior; this subset does not establish every Linux TIME-WAIT reuse policy.

[Controlled TCP loss acceptance](tcp-loss.md) adds actual active/passive SYN/SYN-ACK, data and FIN loss/retry observations, exact streams and peer sequence wrap over both NICs, firmware modes and virtio transports. The independent peer records and packet captures establish this first loss subset; hostile-segment, reordering, persist and complete deadline/fault acceptance remain open.

[Controlled zero-window acceptance](tcp-persist.md) adds stopped-window probes, elapsed backoff and exact recovery to the loss and receive-ordering profiles. [Configured user-timeout acceptance](tcp-user-timeout.md) separately checks real socket errors, independent elapsed deadlines and disabled-timeout recovery. [Old-ACK acceptance](tcp-old-ack.md) rejects poisoned in-window payload/FIN before window learning, then verifies actual challenge ACKs and exact recovery. Other TCP reliability requirements remain open.

## Malformed-input acceptance

`sudo -n make test-tcp-malformed-native` compares native glibc, static musl and
dynamic musl. `make test-tcp-malformed` runs all eight combinations of linkage,
firmware and virtio transport, with virtio-net and e1000 together. Each adapter
receives a poisoned bad-checksum payload, zero/one/overrunning option lengths,
incorrect MSS and window-scale option lengths, and a well-formed unknown option.
Each injection precedes a valid sixteen-byte recovery by a complete 100 ms wait.
The client verifies all 16 request and 112 reply bytes and both stream closes.

Bad-checksum data cannot advance receive ownership. Axiom64 also discards the
five malformed-option segments. Linux can accept their payloads after stopping
option parsing; this comparison permits that robust handling difference.
Both systems must accept the well-formed unknown option before its fallback.
These checks exercise actual packets delivered to real sockets.

`python3 scripts/tcp_malformed/capture.py` audits all 22 original captures,
independent peer records and native monotonic receipts. It checks exact input
encodings, full recovery waits, application bytes, FIN acknowledgments, source
and runtime product hashes, and the contents of both actual boot images.
`python3 scripts/tests/tcp_malformed_capture_test.py` rejects 220 copies with
missing or repaired injections, changed options or payloads, false ACKs,
missing recovery, incorrect FIN ownership or missing final ACKs. The challenge
CI job retains these inputs and results. Complete congestion and hard-device
failure acceptance remain required.

## Captured congestion acceptance

`sudo -n make test-tcp-window-native` and `make test-tcp-window` run three native
libc profiles and all eight mixed-NIC guest configurations. An ACK-gated peer
measures opening flight and growth after one MSS is acknowledged, withholds
further ACKs through two actual retransmission timeouts, then measures recovery.
It advertises a 1024-byte window for a complete 350 ms observation before
reopening it. Each original socket completes 65536 exact forward bytes,
16 reply bytes and both acknowledged FINs.

`sudo -n make test-tcp-fast-native` and `make test-tcp-fast` use the same client
with a separate peer. Three duplicate ACKs must precede one retransmission of
the oldest segment; a fourth duplicate then tests inflation. An advancing ACK
tests deflation before the same receive-window and close observations.

`python3 scripts/tcp_congestion/capture.py` derives flight and byte ownership
from the original packets. It checks negotiated MSS, cumulative ACKs, window
bounds, exact retransmitted bytes, full observation waits, native receipt
clocks and the contents of all four boot images. Guest Reno bounds and Linux's
permitted CUBIC/limited-transmit behavior are checked separately. The RTO
profile retains both actual retry intervals without rounding or rescaling them;
the existing default/configured deadline suites remain separate acceptance.
`scripts/tests/tcp_window_capture_test.py` and
`scripts/tests/tcp_fast_capture_test.py` reject 198 and 242 damaged copies,
including excess flight, receive-window overrun, poisoned or missing retries,
unowned ACKs and incomplete closes. These observations run in the loss CI job.

## Connection pressure and expiry

`sudo -n make test-tcp-pressure` runs the complete three-libc native comparison and
eight static/dynamic, BIOS/UEFI and modern/legacy guest profiles. Each keeps a live
TCP connection on each NIC while 2560 refused/aborted attempts, 5120 listener/child
teardown cycles and enough graceful loopback closes to fill the compact table
exercise reclamation. Listener cycles check queued-child close, listener shutdown,
unread accepted-child reset, full-backlog teardown and an independent live listener.
Admission pressure
must leave both companions usable and all 32 simultaneously held fresh UDP sockets
able to exchange exact bytes. The program waits the full 120 seconds, repeats the
pressure and UDP workload, then completes both companion closes. Conservative guest
admission and Linux's larger native capacity are checked separately.

The coordinator builds clients and prepares immutable images before overlapping
independent observations. `scripts/tcp_pressure_capture.py` verifies all original
frames, checksums, tuple ownership, exact payloads, acknowledgments and FINs. Actual
driver receipts and zero-drop counters must account for every captured IPv4 frame.
Both the application clock and the independent packet clock must observe the full
expiry interval. Source, product, provider and native loader hashes bind the results
to their inputs. `scripts/tests/tcp_pressure_capture_test.py` rejects 198 damaged
observations, including a checksum-valid reply addressed to the wrong UDP socket.
The optional `--quick` client diagnostic does not establish expiry acceptance.

## Path MTU recovery

A validated ICMP destination-unreachable/code 4 hint can lower an established connection's effective send MSS without aborting the socket. The quote must own the emitted tuple, interface and outstanding sequence range. Hints below 68 bytes, nonreducing values and hints that cannot reduce the quoted packet are ignored. A zero next-hop MTU lowers the shared route estimate to its default floor; the legacy decoder can also supply a lower transport candidate for a small quoted packet. Peer-advertised MSS and the local receive MSS remain separate from the path limit.

The sender retains the original unacknowledged bytes and highest transmitted sequence while splitting the outstanding flight. It sends one resized packet, waits for ACK progress, then retransmits the remaining flight within the peer window and congestion allowance. FIN ownership and sequence wrap follow the same cursor. PMTU feedback preserves congestion state, retransmission backoff and configured/default delivery deadlines. Repeated or invalid hints cannot restart those deadlines. `IP_PMTUDISC_DONT` can populate the shared route cache without forcing an immediate transport retry. PROBE can adapt the TCP segment limit while IP output bypasses the learned limit. INTERFACE and OMIT do not accept hints. New active and passive connections use the shared path limit; accepted sockets inherit the listener's discovery policy. Complete discovery-policy and cached-route lifecycle equivalence still require broader acceptance.

Only oversized IPv4 copies belonging to the affected socket are cancelled. Submission retains borrowed storage until the network driver returns, including when a receive callback cancels that packet. Other interfaces and owners keep their queues.

`make test-tcp-pmtu` runs sanitizer models for quote validation, wrap, FIN, partial ACKs, failed enqueue, changing windows, congestion and unchanged deadlines. `sudo -n make test-tcp-pmtu-native` and `make test-tcp-pmtu-sockets` run three native libc profiles and all eight mixed-NIC VM profiles. Each NIC has twelve independent paths, with 4096 bytes in each direction, active/passive opens, valid and legacy hints, consecutive reductions and eight damaged/unowned/nonreducing controls. Separate destination addresses prevent Linux's shared PMTU cache from hiding a later case. Linux accepts an invalid quoted inner IPv4 checksum; the guest retains its stricter validation. The native case explicitly requires recovery from that hint, while the guest requires a later valid hint.

The application records real driver frames and zero-drop counters. `scripts/tcp_pmtu_capture.py` checks original quoted packets, deliberate mutations, observation clocks, MSS values, tuple-specific payloads, full closes and source/product/provider hashes. `scripts/tests/tcp_pmtu_capture_test.py` checks rejection of damaged evidence. The full transport and VM-readiness requirements remain open. The recovery rules follow [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html) and the quote-ownership guidance in [RFC 5927](https://www.rfc-editor.org/rfc/rfc5927.html).

[Quoted ICMP acceptance](tcp-icmp-acceptance.md) adds bounded quote decoding, emitted tuple/sequence ownership, pending connection failures, established soft diagnostics and their timeout/consumption policy. Additional message/address/reconnect/option behavior, complete PMTU policies and route caching, error queues and complete Linux TCP options remain required, along with the controlled NIC and lifetime tests. Actual libc DNS TCP fallback and response ownership are covered by the [resolver tests](dns.md). IPv6 transport, urgent/OOB handling, TLS, full entropy/ISN acceptance and SMP are separate outstanding work. The VM operating system and required workloads come first; HP-specific development follows the readiness review in [HP hardware readiness](feature-roadmap.md), after most roadmap requirements and all prerequisites have evidence. Physical boot tests and installation readiness follow the required HP driver work.

Native packet timing retains the original kernel timestamp and an independent paired realtime/monotonic receipt for every frame. Paired anchors bracket capture startup and completion. The reader requires one clock offset supported by both anchors and all frame pairs and applies that constant translation to the kernel timestamps. Reader scheduling cannot enlarge or compress packet intervals; inconsistent clock offsets reject the evidence. Linux documents the [packet timestamp clock](https://docs.kernel.org/networking/timestamping.html) and [clock domains](https://docs.kernel.org/core-api/timekeeping.html).

The complete PMTU and pressure audit commands require three unique native linkage profiles or all eight guest linkage, firmware and transport profiles. Missing, repeated, unknown or mixed profiles fail before artifact inspection. The per-row auditor remains available for focused diagnosis.
