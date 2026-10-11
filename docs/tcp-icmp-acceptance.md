# Quoted ICMP errors for TCP

IPv4 delivers supported ICMP destination-unreachable, TTL-exceeded and parameter
errors to the TCP connection that owns the quoted transmission. The decoder checks
the complete ICMP checksum, quoted IPv4 version/header/checksum/declared length,
fragment flags, protocol and the eight quoted TCP bytes. It returns an owned value;
packet storage does not escape the decoder. Lookup requires the local/peer addresses,
both ports and any explicit device binding. The quoted sequence must fall within
the inclusive, wrap-aware emitted interval. Closed and TIME_WAIT connections ignore
these errors, and a reused tuple cannot consume the previous connection's sequence.

Active pending connects fail with the corresponding Linux IPv4 errno. Blocking calls,
duplicated descriptions, signal-interrupted connects and retained calls across close
and descriptor reuse observe their connection's failure. Nonblocking calls expose
error readiness; `SO_ERROR` consumes the hard error, and the existing reconnect path
can create a fresh connection on the same description. An unaccepted passive request
owns its exact SYN-ACK sequence. Network, host, TTL and parameter errors can abort
that request; port and protocol errors leave it pending. The listener remains usable.

Established connections keep a soft diagnostic without closing or exposing error
readiness. `SO_ERROR` can read and consume it while the connection stays alive.
Accepted ACK progress also clears it. If delivery later times out, the last remaining
diagnostic becomes the hard error and remains separately consumable as the soft
diagnostic, matching Linux's hard-then-soft error order. Consuming the diagnostic or
making ACK progress restores `ETIMEDOUT` for a later unacknowledged transfer. A failed
guest `SO_ERROR` user copy preserves the pending value.

## Verification

```sh
make test-tcp-icmp
sudo -n make test-tcp-icmp-native
make test-tcp-icmp-sockets
python3 scripts/tcp_icmp_capture.py
python3 scripts/tests/tcp_icmp_capture_test.py
```

The sanitized host test uses an actual minimum quote, every shorter length, repaired
mutations, IPv4 options through the maximum header size, sequence wrap, emitted
ownership, passive requests, soft diagnostics, ACK progress and TIME_WAIT. It also
decodes 50,000 bounded fuzz inputs.

The actual socket fixture runs 57 cases on each of virtio-net and e1000, followed by
128 alternating descriptor reuses with the same client/peer tuples and fresh SYN
sequences. Every later generation receives the actual preceding SYN's stale quote
before its own failure. The client first observes silence, then its owned error.
Four unrelated active/accepted streams and two listeners remain live throughout.
Each stream completes 67 exact request/reply checkpoints during the socket cases,
cross-device errors and reclamation phases; the peer's receive sequence wraps.
Cases include the supported errno mappings, inclusive sequence edge, half-range and
other invalid quotes, IPv4 options, weak-host delivery across devices, explicit device
binding, blocking/retained/interrupted connects, reconnect, established diagnostics,
real blocked reads, consumed diagnostics, ACK recovery, passive replacement and a
complete FIN exchange before late TIME_WAIT errors.

Native glibc and source-built static/dynamic musl run in three isolated Linux network
namespaces with offloads disabled and zero-drop captures. The dynamic comparison
uses the recorded source-built loader. Guest static/dynamic musl cover all eight
BIOS/UEFI and modern/legacy virtio combinations, each with both NICs. Kernel, init,
client, provider manifest/library/loader, source and boot-image hashes identify the
actual inputs. Native glibc and loader hashes identify the installed comparison.
CI also retains the installed native libc package version and its copyright notice,
so downloaded distribution libraries can be checked against those actual hashes.

The auditor independently decodes captured Ethernet/IPv4/TCP/ICMP bytes and checks
checksums, exact earlier quote ownership, literal mutations, receiving devices,
handshakes, replacement requests, successful reconnect, ACK progress and FINs. Each
IPv4 frame must match both the peer journal and an actual packet-socket receipt,
including direction, interface, whole-frame hash and monotonic time. Socket start/end
clocks and actual packets establish the silence and delivery intervals.

The complete matrix requires 22 captures, 1,254 finished cases, 1,408 descriptor
cycles, 4,070 quoted errors, 1,386 stale quotes and 2,948 unrelated-stream checkpoints.
Eleven synchronized corruptions per
capture must be rejected: wrong error, unowned sequence/address, omitted or noncausal
error, stale quote relabeled current, poisoned or omitted recovery, shortened timeout
and a forged product fingerprint, plus an omitted unrelated-stream reply. All 242
damaged PCAP/journal/receipt/input bundles
are retained with rejection reasons and hashes under `build/tcp-icmp-damaged/`.

CI adds `tcp-fault-icmp` to the [complete TCP profile jobs](ci-tcp-profiles.md). All
earlier gates remain required: 43 test jobs, the shared build and the `qemu` aggregate
must pass for the current head. Integration also requires independent downloaded
source, product, library, image, packet, clock and receipt checks for this profile
and the retained TCP, DNS and manager evidence.

## Linux differences and limits

Linux 6.6.87.2 accepts six malformed quote variants that this bounded decoder rejects:
a bad quoted IPv4 checksum, a short declared original length, a wrong IP version,
fragment offset, more-fragments and the reserved fragment flag. The fixture records
those literal native outcomes alongside the stricter guest results. It does not
claim Linux parity for malformed quote admission.

Linux can retain `POLLERR` from an asynchronous error-queue entry after `SO_ERROR`
is consumed. Its retry comparison waits for `POLLOUT` and zero `SO_ERROR`, and records
any residual error readiness. Axiom64 does not yet implement `IP_RECVERR` or
`MSG_ERRQUEUE`; complete ancillary and error-queue behavior remains required.

Fragmentation-needed is reserved for future PMTU recovery and cannot abort TCP as
an ordinary unreachable error. This change does not establish PMTU/fragmentation,
route/device failure recovery, IPv6, all TCP options or the complete socket contract.
The wider releases [#109](https://github.com/frankischilling/Axiom64/issues/109) and
[#121](https://github.com/frankischilling/Axiom64/issues/121) remain open. Required
applications and VM milestones still precede HP development.

The policy uses [RFC 1122 section 4.2.3.9](https://www.rfc-editor.org/rfc/rfc1122.html#section-4.2.3.9),
[Linux `tcp_ipv4.c`](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_ipv4.c)
and [the native kernel's TCP error handling](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/net/ipv4/tcp_ipv4.c)
and [socket error consumption](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/net/core/sock.c).
