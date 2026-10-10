# Per-connection TCP challenge ACK intervals

The synchronized TCP endpoint admits one challenge ACK per connection every 500 ms.
Rejected old/future ACKs, unexpected SYNs, in-window nonexact resets and out-of-window
pure ACKs share this interval. The first request is permitted, including at clock zero.
Elapsed subtraction avoids an overflowing deadline near the clock limit; a backward
reading cannot reopen the interval. Connections have independent state.

The rejected segment cannot update the peer window, deliver payload or consume FIN
sequence space. Valid receive ACKs, receive-window updates and out-of-window data/FIN
retransmission replies retain their ordinary behavior. An exact-sequence reset still
closes the connection immediately. Failed output enqueue leaves one permitted ACK
pending; repeated invalid input does not create another. Challenge input leaves the
configured user-timeout progress deadline intact.

This follows the per-socket default in [pinned Linux TCP input](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_input.c)
and [its initialization](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/net/ipv4/tcp_ipv4.c).
[RFC 5961 section 7](https://www.rfc-editor.org/rfc/rfc5961.html#section-7) describes ACK
throttling. This implementation uses the fixed default. Remaining lifetime, TIME-WAIT
and hostile-input acceptance stays in [#121](https://github.com/frankischilling/Axiom64/issues/121)
and [#109](https://github.com/frankischilling/Axiom64/issues/109).

## Verification

`make test-tcp-connection` runs the production encoder/checksum/decoder under address
and undefined-behavior sanitizers. Fifty cases cover mixed invalid kinds, independent
connections, first response, zero/near-limit clocks, wrap, interval boundaries,
suppressed-input silence, failed enqueue, ordinary data/FIN ACKs, exact resets and
unchanged user timeout. The new burst assertion fails against the preceding engine.

`make test-tcp-challenge-native` compares glibc, static musl and dynamic musl in private
network namespaces. `make test-tcp-challenge` runs both musl clients under BIOS/UEFI and
modern/legacy virtio, alongside e1000. Four socket flows run concurrently so active and
accepted connections can respond within the same 500 ms interval. Each flow sends and
recovers 65,536 exact bytes in each direction and retains actual handshake/data/FIN loss
and retry checks, including peer sequence wrap.

Before concurrent VM opens, the client observes a real 1,200 ms setup wait. QEMU 8.2.2
[delays queue flushing for one second after an e1000 receive-control write](https://github.com/qemu/qemu/blob/v8.2.2/hw/net/e1000.c#L393).
Starting both adapters immediately can queue the first wire frames and compress their
peer observation interval. The setup wait settles that initial queue; all protocol
loss timers and challenge silence requirements retain their full durations.

Each flow runs eight rounds, one for every invalid control shape. A round injects a
trigger, observes its actual challenge, sends one mixed eight-kind burst immediately
and another after 100 ms, then observes silence until at least 650 ms after the response. Valid data
starts at the unchanged receive edge after the final barrier. The complete matrix
contains 22 captures, 44 flows, 5,984 invalid injections and 352 challenge replies.

`python3 scripts/tcp_challenge_capture.py` compares every peer/guest TCP frame with
the independent PCAP, checks both actual clocks, full silence, per-connection replies,
unchanged sequence edges, exact streams and original loss retries. Native capture
sockets must report zero drops. Reports and packet logs use `build/tcp-challenge-*`.
`python3 scripts/tests/tcp_challenge_capture_test.py` rejects 1,760 synchronized damaged
cases, including missing triggers/bursts/replies, extra tagged or untagged replies,
poison consumption, changed control shapes, shortened real waits and concealed frames.
The challenge profile writes the live QEMU capture to Linux temporary storage, then
copies its complete raw bytes to the build evidence directory after QEMU exits. This
keeps capture-file I/O off the packet delivery path when the checkout is on a mounted
host filesystem. Both clocks must still place the entire burst within 250 ms and
retain the full silence barrier. All earlier TCP profiles and the full
manager/filesystem gates remain required in CI.
