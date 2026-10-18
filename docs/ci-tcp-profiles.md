# Complete TCP profiles in parallel CI jobs

The CI matrix runs loss, receive ordering, zero-window persist, configured user timeout,
old-ACK rejection, [challenge ACK intervals](tcp-challenge-ack.md) and
[quoted ICMP errors](tcp-icmp-acceptance.md) in seven isolated
jobs. Each receives the exact source/build artifact and retains three native libc
comparisons, eight VM firmware/transport/linkage cases, both adapters, real protocol
waits and independent positive/negative packet checks. Ordinary TCP sockets remain a
separate job. The earlier six profiles keep their established commands and records.

The profile matrix names are `tcp-fault-loss`, `tcp-fault-reordering`,
`tcp-fault-persist`, `tcp-fault-timeout`, `tcp-fault-old-ack` and
`tcp-fault-challenge` and `tcp-fault-icmp`. Each publishes `axiom64-evidence-<suite>` and
`axiom64-<suite>-fixtures`, where `<suite>` is the complete matrix name. Download all
seven pairs to audit the implemented wire profiles, including twenty-eight static/dynamic images.
The loss job additionally measures ACK-gated congestion and receive-window
ownership. RTO and duplicate-ACK observations each retain three native libc
profiles and all eight guest configurations, original packet clocks, two
inspected boot images and exact completed streams. Their independent auditors
reconstruct actual flight, negotiated MSS, retransmitted byte ranges, recovery
bounds and the advertised 1024-byte receive window. Native CUBIC and guest Reno
bounds are checked separately. The two observations reject 198 and 242 damaged
captures respectively; existing deadline and retransmission tests remain required.
See [captured congestion acceptance](tcp.md#captured-congestion-acceptance).
The challenge job also runs malformed TCP checksum and option injections through
three native libc profiles and all eight guest configurations. Both adapters
must preserve exact application bytes and acknowledge both FINs after seven
injections apiece. The independent audit opens both additional boot images,
verifies their actual kernel, client, init, loader and boot script, and rejects
220 damaged capture copies. This adds no matrix job. See
[malformed-input acceptance](tcp.md#malformed-input-acceptance) for commands and
the documented Linux option-handling difference.
The quoted-error job also runs the [PMTU recovery matrix](tcp.md#path-mtu-recovery),
with three native linkages, eight VM profiles and both adapters. It publishes the
PMTU sources/products, input manifests, original captures, audits and damaged-evidence
controls in the same evidence/fixture pair. This adds no matrix job.
The same job runs the full [admission and TIME-WAIT pressure matrix](tcp.md#connection-pressure-and-expiry).
Three native linkages and eight guest profiles keep both NIC companions alive during
saturation, verify fresh UDP sockets and observe the complete 120-second expiry.
Native observations run concurrently in separate network namespaces; at most four
guest VMs run concurrently, with unique peers, captures and logs. Prepared images
and manifests remain immutable during observation. Independent audits check actual
packet bytes, clocks, driver receipts and source/product hashes; 198 damaged-evidence
controls include wrong socket ownership and shortened observation intervals.
The [disconnect/reconnect profile](tcp.md#linux-socket-integration) runs in that job
with three native and eight guest profiles. It checks successor sequence bounds,
completed tuple guards, independent destinations and exact old/new streams.
Queued-copy cases retain old output through cancellation, then recover the same
description and tuple while both NICs remain active. Both complete cohort lists
are required; missing or duplicate profiles fail. Damaged-evidence controls cover
packet ownership, sequence translation, options, close/reset history, real queue
backlog, callback ownership, observer fingerprints and clocks, client results,
source hashes and cohort completeness. Reconnect guest profiles use two isolated
VMs concurrently; all eight firmware/transport/linkage combinations retain their
complete observations.
Congestion, malformed-input, quoted-error, PMTU, pressure, reconnect and recovery native
glibc comparisons publish the exact libc and loader bytes under
content-addressed paths. Input manifests bind both retained libraries to the
actual host fingerprints, so downloaded evidence can be checked on another host.
An actual local comparison of all eight profiles used the same inspected images,
clients and source with one and two workers. Producer time fell from 259.623 to
130.576 seconds; each cohort passed 16 captures and rejected the same 298 damaged
cases. This measures the reconnect workload, not the full workflow, and precedes
the added three-open revisit case.
The [interface recovery profile](tcp.md#linux-socket-integration) also runs in
that job. Three native linkages and eight guest profiles retain exact streams
through administrative down/up before enqueue and after confirmed output holds,
with companion traffic on the other NIC. Additional holds retain the complete
4500-millisecond observation and verify recovery after actual IPv4 copy expiry.
Connected-route withdrawal and explicit host-route deletion on each NIC require
fresh-connect failure, retained bytes, live companion traffic and exact recovery.
Physical-carrier cases preserve administrative state and gate the companion
echo on actual link loss before queuing selected bytes. Each stream carries
6224 data bytes and four control bytes. Independent audits verify complete
streams, ACKs, control barriers, actual queue, expiry, route and carrier
observations; 513 damaged-evidence cases cover packet, queue, expiry, route,
carrier, result, source and cohort corruption. Guest debugger
observations do not replace the separate retransmission timing gates.
The build job publishes corresponding source, test inputs and compiled products.

The [full default-lifetime profile](tcp-default-lifetime.md) adds `tcp-lifetime-native`
and `tcp-lifetime-{bios,uefi}-{modern,legacy}`. Its native job overlaps three isolated
libc observations; each guest job overlaps two 512 MiB observations after sequential
fixture construction. All observe the complete default interval. Each publishes its
scoped evidence; the four guest jobs also publish their generated static/dynamic images.
Download all five evidence artifacts and all four fixture artifacts to audit this
profile's 22 captures, 264 flows and 396 damaged-evidence cases. Native packet
timestamps remain unchanged; separate monotonic receipts establish elapsed time
and have their own corruption checks within the existing jobs.

All earlier non-profile suites remain present. `fail-fast: false` preserves evidence
from other jobs when one fails. The required `qemu` aggregate checks the build and
entire matrix. The complete workflow requires all 209 jobs, including its aggregates.
Failed, cancelled, missing or skipped
profile acceptance blocks integration.

The accepted [five-profile serial run](https://github.com/frankischilling/Axiom64/actions/runs/38082099595)
and [parallel run](https://github.com/frankischilling/Axiom64/actions/runs/38083705139)
completed every required gate. TCP acceptance feedback after the shared build fell
from 1,836 to 566 seconds; whole-workflow elapsed time fell from 2,240 to 1,180 seconds.
The serial run also spent 1,305 seconds downloading inputs in its critical carrier
job, so the whole-workflow difference includes runner/setup and queue effects. The
protocol commands and real waits retained their full durations.

Later shared-input, storage-profile and paired-worker changes reduced the complete
workflow from 401 to 209 jobs. Measured runner time fell from 189563 to 156693 seconds,
with all 3840 storage fault cases retained. Broader timing work remains evidence driven.
TCG stays the default; the complete manager matrix and VM-before-hardware requirements remain in force.
