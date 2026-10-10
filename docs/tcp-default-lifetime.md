# Default TCP delivery lifetime

[#155](https://github.com/frankischilling/Axiom64/issues/155) covers unanswered established
data, FIN and zero-window probing. TCP_USER_TIMEOUT remains zero by default. Zero selects
a finite 924600 ms default delivery period; a positive value selects the configured
deadline, including values longer than the default.

The default period starts when output ownership commits the first outstanding sequence
or persist probe. Failed submissions leave that start untouched. Forward acknowledgment
progress renews the period while sequence remains outstanding. A completely acknowledged
send clears it, allowing a later send to start a fresh period. Retransmissions, ordinary
duplicate ACKs and rejected control segments cannot postpone failure indefinitely.

A validated zero-window receiver may keep responding without accepting application
bytes. Those responses renew the default period, as required for a responsive stopped
receiver. Reopening starts a fresh delivery period for outstanding sequence. Configured
user timeout continues to measure stalled progress independently of those responses.
An empty FIN queued behind a closed window starts its configured observation with the
first owned probe. Backward clock readings cannot move the default start earlier.

The 924600 ms threshold follows the pinned Linux default model: 15 retries, a 200 ms
minimum RTO and a 120 second maximum produce an elapsed threshold rather than a fixed
number of this engine's retries. Axiom64 retains its existing one-through-60-second
backoff. Linux processes expiry at its actual timer callbacks; comparisons must measure
the complete interval instead of requiring identical retry counts or timestamps. This
subset does not complete handshake policy, R1 route advice, ICMP/MTU/device errors or
every Linux zero-window policy when packets were already in flight before closure.

Last close releases the storage and binding of an already closed endpoint immediately
when no output remains. A pending reset still awaiting output ownership stays on the
poll path. The actual socket profile consumes errors, closes the failed description,
and binds and listens on its former local port without a sleep or SO_REUSEADDR.

## Actual socket and packet acceptance

`make test-tcp-connection` runs 27 lifetime regressions through the production encoder,
checksum, decoder and connection engine. They cover first output ownership, failed
submission, exact boundaries, zero/near-limit/backward clocks, sequence wrap, progress,
fresh send periods, configured overrides, independent connections, responsive recovery,
empty FIN and stale/future zero-window ACKs. Supplied policy time makes these fast
regressions; the real elapsed observations below remain required.

The same C program runs with glibc, static musl and dynamic musl on Linux, and with both
musl linkages in the VM. Each application opens 24 independent flows concurrently:
active and accepted sockets for six cases on each NIC.

- Unanswered data with an open window and TCP_USER_TIMEOUT zero.
- Unanswered pure FIN with an open window and TCP_USER_TIMEOUT zero.
- Unanswered probing with the window closed from the handshake and the option zero.
- A responsive stopped receiver with the option zero, held closed for the full default
  interval plus sixty seconds, followed by exact 2048-byte streams in both directions
  and acknowledged FINs through wrapped peer sequence space.
- Unanswered data with a configured 984600 ms deadline, longer than the default.
- An empty FIN behind a closed window with a configured 2500 ms deadline. This short
  configured case supplements the complete default observations.

Failure cases check ETIMEDOUT through blocking receive or POLLERR/SO_ERROR, then cleared
SO_ERROR, EOF, EPIPE and immediate local-port reuse. No socket I/O deadline substitutes
for failure. Each flow has its own option, sequence, observation and result. The process
alarm and host runner deadline only bound a failed suite; neither establishes success.
Concurrent result records use one bounded write, preserving complete musl output.

`make test-tcp-lifetime-native` runs three concurrent observations in disposable peer
and client network namespaces. It reads actual retry defaults and leaves host settings
unchanged. Every NIC has a separate zero-drop kernel-receipt timestamp capture.

`make test-tcp-lifetime` covers BIOS/UEFI, modern/legacy virtio and both musl linkages,
with e1000 alongside virtio-net. Fixture construction is sequential; at most two
512 MiB QEMU observations run concurrently. CI assigns the four firmware/transport
combinations separate jobs, each observing both linkages for the full interval.

`python3 scripts/tcp_lifetime/capture.py` requires all five reports, totaling 22 captures
and 264 flows. CI uses `--report` for each complete native or paired guest scope. The
independent decoder validates packet bounds, checksums, options, tuples, sequence and
payload. It matches every PCAP packet to peer evidence, compares both clocks throughout
the full period, checks exponential/capped retries, forbids hidden progress, verifies
non-progress probe answers, and checks application option/error/owner-release records.
Clock disagreement invalidates the evidence; packet times are never rescaled.

`python3 scripts/tcp_lifetime/damaged.py` rechecks the actual positive captures and
rejects 17 classes per capture. Packet changes update the corresponding peer records
and repair checksums. Cases remove a retry, FIN, probe, probe answer or reopening;
alter ACK progress, the window, probe sequence or recovered bytes; falsify options,
errors, reclamation or application deadlines; shift a packet clock; or shorten the
responsive observation. The complete matrix requires 374 rejected cases.

The existing six TCP fault profiles and every other CI suite remain required. The
five new jobs bring the full workflow to 44 jobs including the aggregate `qemu` gate.
Build inputs retain all three new compiled clients; evidence and every generated
guest image remain in the corresponding scoped artifacts. Integration requires
current-source full CI and independent published evidence, including the retained
manager/startup/filesystem matrix. Local regressions and individual observations do
not complete #155, its TCP parents, or the VM workloads required before HP development.

The contract follows [RFC 9293 section 3.8.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.3)
and [zero-window operation](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.6.1),
with behavior compared against [Linux tcp_timer.c](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_timer.c),
[TCP constants](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/include/net/tcp.h)
and [Linux defaults](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_ipv4.c).
