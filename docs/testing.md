# Guest tests and CI

`python3 scripts/tests/account_rotation_disk_test.py -v` checks bounded host-memory device staging, disk fallback, exact copyback after success or guest failure, and retention when the evidence destination rejects copying. Rotation's small device files use this staging while the NBD backend retains its independent cache, flush and fault semantics. The original guest deadlines and native filesystem checks remain required. [VM timing](ci-vm-timing.md) records the focused host-storage comparison and remaining complete-run gates.

Disposable NBD startup retains `backend-startup.json` beside each backend log.
It records the actual command, executable fingerprint, original five-second
socket bound and observed outcome. A failed process is sampled before termination:
bounded proc state, wait channel, memory mappings and host CPU/memory pressure
remain available even when the backend log and block trace are empty. Launch
errors and early exits also retain their status and close the owned log handle.
`python3 scripts/tests/nbd_startup_test.py -v` exercises actual failed processes,
including a stopped child that must hit the unchanged five-second bound and be
reaped. These diagnostics preserve the failure verdict; they do not establish the
cause of a startup stall or grant another attempt.

`sudo -n python3 scripts/ipv4_alias_native.py` compares labelled address lifetimes with three native Linux linkages and two captured TAP links each. The normal guest IPv4 profiles exercise the same alias client on both adapters. Alias packets must retain their selected source and hardware identity across primary deletion. Independent capture checks run after each native or normal guest comparison; twenty-two damaged fixtures per adapter must fail. Captures, original logs and compressed negative fixtures remain in the evidence artifacts. Sanitizer inventory/route checks and thirteen damaged peer controls run in the existing build job; native alias evidence stays in the network job. Both musl IPv4 clients compile with the pinned target UAPI helper. Complete current-revision acceptance remains required.

The native IPv6 router comparison runs on a dedicated reference host through
`scripts/native_address_worker.py`. It selects one CPU shared by the calling
process and unbound workers, records the actual masks and child affinity, then
restores the original settings. The stock SMP kernel, all three libc/linkage
profiles, both adapters, original packets, expected flags and sixty-second
profile deadlines remain in use. This scheduling constraint prevents a measured
Linux address-worker race from losing an immediate deprecation update. It does
not change guest scheduling or the one-second flag observation bound.

`sudo -n make test-native-address-worker` checks actual CPU-mask ownership,
successful and failed commands, SIGTERM/SIGINT cancellation, child retirement
and competing ownership. The native router receipt is retained as
`build/ipv6-router-native-worker.json`; these controls retain their logs and
results under `build/native-address-worker-tests/`. The wrapper changes the
host's global unbound-workqueue mask temporarily. Use the native target only on
a dedicated test host. An unexpected outside mask change fails the run while
preserving that other owner's value.

IPv6 ownership conflicts publish both adapters' freshly queried metadata before
waiting for either acknowledgment. This preserves the tentative candidate while
the other adapter waits for its first DAD probe. Strict owner flags, original
DAD timers, ten-second control bounds and complete quiet windows remain in use.
`python3 scripts/tests/ipv6_owner_pair_test.py -v` runs the actual C query/send/wait
chain against controlled netlink replies and the actual peer validator. Its
recorded-delay unit model reproduces a second adapter becoming ready during the
first wait; it supplies no runtime timing qualification. Full native and guest
ownership comparisons remain required.

IPv6 TCP loss comparisons use `sudo -n make test-tcp6-wire-native` and
`make test-tcp6-wire`. The existing TCP loss CI job runs all three native
linkages and eight guest firmware/linkage/transport profiles, each with
virtio-net and e1000. It retains both complete evidence directories, including
boot images, source snapshots, exact clients, independent captures and damaged
controls. It adds no job or replacement coverage. The default output directories
must be new; use `scripts/tcp6_test.py --output-directory PATH` for another run.
`python3 scripts/tcp6_audit.py DIRECTORY --output-directory NEW_PATH` independently
reopens existing evidence without rerunning its producer. Kernel realtime packet
timestamps remain untouched. A native monotonic arrival bracket of at most
fifty milliseconds supplies a conservative lower bound for each retry interval;
an overdue reader fails capture acceptance. The quiet-queue observer check is
`sudo -n python3 scripts/tests/tcp6_observation_test.py`. These checks cover the
active/passive loss subset; ICMPv6, PMTU and full TCP6 lifetime acceptance remain
open.

`sudo -n python3 scripts/tests/tcp6_native_cleanup_test.py` injects a peer failure
after an actual native client starts. The wrapper and client must retire as one
owned process group, and both TAP interfaces must disappear.

`sudo -n make test-tcp6-controls-wire-native` and
`make test-tcp6-controls-wire` compare IPv6, mapped and pure IPv4 TCP controls.
Each family uses three native and eight guest profiles on both adapters, with
the same pinned musl clients and loader in native and guest executions. Actual
router advertisements change default hops from 41 to 51. Eleven active byte-checked
exchanges per adapter cover traffic-class/TOS cache invalidation, zero and
explicit IPv6 hops, normalized unchanged values and device reselection. A
checksum-valid duplicate FIN arrives after the application releases its final
descriptor; the detached reply must use the measured default hop/TTL and retained
class/TOS. IPv4 wire output retains its independent live TTL and TOS.

Two passive children add five exchanges per adapter. The first request withholds
its final ACK while a duplicated listener descriptor changes hops, class, TTL
and TOS. Its natural SYN-ACK retry must use the updated listener controls; the
accepted child snapshots those controls at the final ACK. A later listener
update affects the second child while the first retains its own values. Both
children exchange bytes after the final listener descriptor closes. The first
child closes and answers a duplicate FIN while the second exchanges more bytes.
The second then closes and answers its own duplicate FIN.
The one-second engine retry timer, original guest clock and established
850-millisecond physical handshake observation threshold remain unchanged.

The existing packet harness retains the 150-second execution deadline, original
capture clocks, zero native drops and fifty-millisecond arrival brackets.
Ninety damaged packet/log variants per capture are serialized, reopened and
rejected through the real reader. Header and echo mutations have repaired
checksums; native frame fingerprints are rebound to reach semantic checks.
`python3 scripts/tests/tcp6_control_wire_evidence_test.py` reopens all six evidence
directories and requires every profile, actual image and matching native/guest
program. The 33 profiles retain 66 captures, 198 flows, 1,056 exchanges and 1,584
scalar snapshots. Output is retained under `build/tcp6-controls-*-wire/`. Broader
passive behavior, route/source/device lifetimes and complete TIME-WAIT expiry
acceptance remain required.

`sudo -n make test-tcp6-source-lifetime-native` and
`make test-tcp6-source-lifetime` compare established global TCP sources across
address removal. Explicit and automatically selected streams retain their
original source while a companion address keeps the prefix route usable. A real
companion exchange completes before the retained-source send. Fresh explicit
binds to the removed address fail; fresh automatic streams select the companion.
Three output blocks per stream follow withdrawal, normalized class changes and
device unbinding. Ethernet barriers observe those exact packets without sending
TCP input to a missing local destination route. The original source is restored
before cumulative acknowledgment, another byte-checked echo and complete close.

The shared runner retains all three native and eight guest profiles, both
adapters, matching native/guest programs and loader, original 150-second case,
120-second alarm, five-second I/O and ten-second barrier bounds. Independent
readers reject 112 serialized, checksum-repaired packet/log changes per capture.
`python3 scripts/tests/tcp6_source_lifetime_evidence_test.py` reopens all 22
captures and both actual images, verifies 88 flows and 264 output blocks, and
requires identical complete sources and pinned native/guest clients. Half of
those output blocks occur while the source is withdrawn. Finite source expiry,
route/device removal and full TCP lifetime acceptance
remain required.

`sudo -n make test-tcp6-scoped-source-native` and `make test-tcp6-scoped-source`
compare explicit and automatic link-local streams after source withdrawal. Both
adapters use identical IPv6 addresses and ports in separate zones, with distinct
MAC owners and lane-specific bytes. These rounds run sequentially; the separate
isolation suite covers simultaneous streams. A fresh bind rejects the removed
source in its own zone while the same address still binds in the other zone.
A real automatically selected companion stream completes before retained-source
output. Hop/class updates retain the original source; restoration precedes
further TCP input, byte-checked echo and complete close.

After the first echo is acknowledged, a quiet interval clears device binding and
reads both names with zone zero, then restores binding and reads the original
interface zones. No TCP input or output is allowed during that cleared-zone
interval. Binding is restored before source withdrawal or further data. The
fixture removes only its MAC-derived automatic link-local candidate so native
and guest automatic selection see matching addresses.
The scoped peer also validates router solicitations from that configured
companion. The source-handshake replay tests include an actual companion-source
solicitation and checksum-repaired source, owner, option and header controls.

`python3 scripts/tests/tcp6_scoped_source_evidence_test.py` reopens all three native
and eight guest profiles, complete matching sources, identical musl clients and
loaders, both actual images and 22 captures. It requires 88 flows, 264 output
blocks, 132 withdrawn-source blocks, 308 getter snapshots, 44 quiet intervals and
44 other-zone bind witnesses. It rejects 4,588 serialized packet/log/zone/clock
controls, 32 product controls and six matrix controls. Checksums and native
fingerprints are rebound for semantic controls. Original 150-second execution,
120-second alarm, five-second I/O, ten-second barrier and capture-clock bounds
remain. Cleared-zone wire routing, route/device removal, broader expiry and
complete networking acceptance remain required.

`sudo -n make test-tcp6-zone-route-native` and `make test-tcp6-zone-route`
measure actual TCP routing after device binding is cleared. Each adapter starts
one explicitly sourced and one automatically sourced stream. Both zones retain
the same link-local addresses; each stream keeps its complete TCP tuple and
sequence across five byte-checked exchanges. A bound exchange uses its original
link. Clearing binding selects the other link's preferred static peer host route
(metric ten). Deleting that route selects the surviving original-link route
(metric twenty); restoring it reselects the other link. Rebinding returns output
and complete close to the original interface. Hop/class controls remain 37/168
through both route changes. Two-link Ethernet fences wait for actual echo ACKs
before each mutation.

The independent reader combines both physical captures without imposing a
synthetic cross-capture clock order. It checks each packet against its own
link's ordered fences, exact MAC owner, full tuple, payload, sequence and echo.
Actual raw route dumps retain the two/one/two host-route inventories. Getter
snapshots retain zero zones while unbound and actual interface zones after
rebinding. Native clocks still require zero drops and original arrival brackets.

`python3 scripts/tests/tcp6_zone_route_evidence_test.py` requires all three native
and eight guest profiles, matching sources and musl clients/loaders, both actual
images, 22 captures, 44 flows, 220 exchanges, 220 getters, 132 route snapshots,
880 transition fence pairs, 44 route withdrawals and 44 restorations. It rejects
5,908 serialized packet/log/route/fence controls, 32 product controls and six matrix
controls. Each corrupted capture is reopened beside its unchanged companion;
checksums and native fingerprints are rebound for semantic controls. The original
150-second case, 120-second alarm, five-second I/O, ten-second barrier and capture
bounds remain. Source withdrawal during these route transitions, actual interface
removal and full scoped lifetime acceptance remain required.

`python3 scripts/tests/tcp6_source_handshake_test.py` replays three actual TCP
frames from a retained failed observation. The final handshake ACK carries the
first payload; the peer checks its acknowledgment and sequence before processing
those bytes. A separate empty ACK remains valid. Wrong sequences, acknowledgments,
flags, source ownership and payload still reject. This replay qualifies the
observer; complete native and guest runs remain the runtime gate.

`python3 scripts/tests/manager_link_startup_test.py` forces a real QEMU debugger
bind failure before guest execution and requires its stderr and command record
to survive teardown. Carrier/failure runs use a private Unix debugger socket and
retain emulator commands and exit status in their packet evidence. Existing
hardware observations, guest deadlines and acceptance checks remain required.

The combined scoped-source and route comparison runs with
`sudo -n make test-tcp6-zone-source-route-native` and
`make test-tcp6-zone-source-route`. An admitted explicit or automatic stream
retains its tuple after the source is removed only from its original zone.
Fresh same-zone binds fail while the same address remains valid on the other
adapter. A fresh automatic companion selects the remaining local address and
completes actual traffic before binding is cleared. The retained stream crosses
the preferred route and its fallback while the original source stays withdrawn.

Native Linux can emit the retained fallback packet while refusing its reply on
the interface whose local destination was removed. Both physical fences wait
for actual fallback output before the client queries the absent source and
fresh-bind denial. The client restores ownership through netlink and reopens the
inventory before a separate fence releases the exact echo. That fence waits for
the actual TCP acknowledgment. Route restoration, rebinding and complete close
then retain the original five exchanges and header/getter checks.

`python3 scripts/tests/tcp6_zone_source_route_evidence_test.py` requires three
native and eight guest profiles, matching actual musl clients, both images and
22 captures. It reopens 44 retained and 44 companion flows, 264 output blocks,
220 source inventories, 352 fresh-bind observations, 132 route snapshots and
1,056 physical fence pairs. Every original native capture frame remains bound to
its original clocks. A lossless packet subset goes through the existing route
decoder with unchanged bytes and timestamps; the additional decoder checks all
companion frames and ownership fences. It rejects 8,526 serialized capture/log
controls, 32 product controls and six matrix controls. Full 150-second execution,
120-second alarm, five-second I/O, ten-second barrier and capture-clock bounds
remain. Actual interface removal, broader expiry/reconnect and complete scoped
lifetime acceptance remain required.

Storage CI waits until the current network suite owns a runner before releasing
its administration and rotation matrices. `scripts/ci/storage_admission.py`
reads this run's exact attempt through the
[workflow jobs API](https://docs.github.com/en/rest/actions/workflow-jobs).
It requires the current source head, unique job identity, an assigned runner and
an executed step. A queued job's `started_at` value does not establish admission.
A terminal network result also releases unrelated storage coverage; the original
aggregate still requires the network suite to succeed.

The admission job has only contents/actions read permissions and checks out the
source tree. It polls every fifteen seconds for at most one hour, with its
own 65-minute job deadline. Invalid, stale or incomplete metadata, API errors and
an unobserved start fail this required job. Every original guest observation and
job deadline remains unchanged. Once admission is observed, storage matrices use
the available runner pool without fixed per-matrix caps. All original 210 jobs
and 304 steps remain, alongside one required admission job with three steps.
The complete workflow therefore requires all 211 jobs and both aggregates.

The complete fixed-cap comparison reduced network admission after the build
from 2,693 to 1,128 seconds, but overall executed workflow span grew from 7,565 to
8,617 seconds. The earlier full workflow failed while the later one passed all
210 jobs; different revisions and runner conditions prevent a causal speedup
claim. The fixed bounds did not demonstrate a complete workflow improvement.
The observed-start policy requires a new complete hosted run and timing
comparison. `python3 -B scripts/tests/storage_admission_test.py -v` checks real
recorded job metadata, run/attempt ownership, queued versus executed steps,
bounded waiting, local HTTP pagination and authentication failures.

The network CI job starts its complete native ICMP/fragment/PMTU comparison
alongside the original Ethernet guest matrix with
`python3 scripts/ci/network_window.py run`. A shared build finishes before either
worker starts. Native profiles use three private network namespaces; guests use
their existing isolated emulated devices. The supervisor retains separate logs,
actual overlap intervals and immutable program hashes, waits for both original
commands, propagates either failure and retires worker process groups.

`python3 scripts/ci/network_window.py audit` reopens all six native captures and
their preflight, fragment-expiry, PMTU and lifetime evidence at the original
comparison step. Every original three-profile case remains required, including
the sixty-second fragment and ten-minute PMTU lifetimes. The job keeps its
original deadline, all guest cells, negative controls and artifact uploads. Full
hosted timing measurements remain necessary before claiming a CI speedup.

`sudo -n make test-tcp6-pending-source-native` and `make test-tcp6-pending-source`
retain all three native and eight guest profiles for four additional rounds per
adapter: a connect bound before source withdrawal, explicit and automatic active
opens awaiting SYN-ACK, and a passive request awaiting its final ACK. A real fresh
companion exchange and close proves route usability before each observed retry.
Fresh binds reject the removed source. The peer withholds handshake input until
source restoration, then checks the exact echo, FINs and final descriptor release.
The original one-second transport timer and all existing harness bounds remain;
the independent wire lower bound is the established 850 ms allowance for guest ticks.

`python3 scripts/tests/tcp6_pending_source_evidence_test.py` requires all 22
captures, both actual images, 176 flows and 88 pending handshakes, with matching
complete sources and native/guest programs. It rejects 870 serialized controls
covering source ownership, natural retry timing, handshake sequence, companion
selection, restoration ordering, close, scalar records and native arrival bounds.
Checksums and native fingerprints are rebound so altered packets reach the
semantic checks. Scoped withdrawal, reconnect, finite expiry and route/device
removal remain required.

`sudo -n make test-tcp6-source-expiry-native` and `make test-tcp6-source-expiry`
repeat the four pending-source cases through actual address lifetime retirement.
Netlink configures a five-second valid lifetime and two-second preferred lifetime;
the client observes successful fresh binds followed by `EADDRNOTAVAIL`. It never
deletes the selected source. Before/after route dumps retain an independent peer
`/128` route, and a real companion exchange proves reachability after expiry.
This avoids mixing source retirement with the prefix route's lifetime update.
The peer observes the original natural SYN/SYN-ACK retries, withholds handshake
input until restoration, then checks the exact echo and complete close.

The independent reader requires at least 4.85 seconds between the barrier before
configuration and the observed retired address, accounting for packet arrival
brackets and guest ticks without changing the five-second lifetime. All original
transport, I/O, barrier, alarm and harness deadlines remain. The complete three
native/eight guest matrix retains 22 captures, 176 flows, 88 pending handshakes
and 176 surviving host-route snapshots. Run
`python3 scripts/tests/tcp6_source_expiry_evidence_test.py` to reopen actual images,
matching programs and complete sources, and reject 1,398 packet/log/timing/route
controls. Broader address and route expiry, established finite-source behavior,
reconnect, scoped withdrawal and every existing long cache-expiry window remain
required.

`sudo -n make test-tcp6-errors-native` and `make test-tcp6-errors` exercise 62
ordinary ICMPv6 TCP cases on each adapter through all three native and eight
guest profiles. They cover thirteen error classes during active, passive and
established operation, shared error consumption, acknowledged recovery and ten
altered quotes. Readers reconstruct actual quotes, passive request generations,
exact streams, half-closes and conservative monotonic observation bounds.
Serialized damaged captures and logs must fail after reopening. The malformed
quoted-version case preserves the measured native/guest difference described
in [IPv6](ipv6.md); it does not establish complete quote-parser equivalence.
Native ordinary-error runs select one allowed CPU before starting collectors.
The actual C client, wrapper and both capture threads retain kernel affinity
records; profiles rotate through the original allowed CPU set. Independent
readers reject seven reopened CPU, namespace and process-record changes per
profile. The stock Linux kernel keeps its SMP configuration. Other TCP suites
retain their existing scheduling policy. Packet ordering, original timestamps,
zero-drop checks, fifty-millisecond arrival bounds and all deadlines remain.
Source capture retains exact Git inputs in a checkout and bounded public source
roots in the exported CI tree. Builds, downloads, private files and Python caches
remain outside that snapshot; private or external link targets reject.

`make test-ipv6-error-record` exercises the actual ICMPv6 metadata formatter with
a retained interrupted record. A simulated kernel diagnostic follows every write;
the complete original fields and hexadecimal padding must occupy one bounded
write. A partial write fails. The original interrupted log remains rejected by
the unchanged metadata reader. Native and guest error cohorts retain every
scenario, packet check, clock and deadline.

`sudo -n python3 scripts/proc_retirement_test.py` exercises actual native thread
retirement with private file tables across both libc providers and glibc, with
static/dynamic linkage. Each profile requires an observed retirement wait across
64 cycles; a live-task control must fail. The fixture retains its executable,
dynamic loader, compiler inputs, original clocks and ninety-second deadline.

`sudo -n make test-tcp6-scoped-native` and `make test-tcp6-scoped` retain the full
TCP loss workload on identical link-local addresses and bound ports across two
interface zones. A same-zone bind must still report `EADDRINUSE` after close,
before the other zone opens the identical tuple. Actual local/peer scope IDs,
all 65,536 bytes in each direction,
sequence wrap, three retransmission classes and acknowledged half-closes remain
required. Independent readers reject missing or false scope results as well as
false retained-port results, damaged packets, clocks, compiler products and
incomplete matrices. This initial
cohort leaves cross-zone injection, source/device removal and wider connection
lifetime acceptance open. It adds commands and retained artifacts to the existing
TCP loss job while preserving the global-address workload and every deadline.

`sudo -n make test-tcp6-pmtu-native` and `make test-tcp6-pmtu` exercise 22 IPv6
TCP Packet Too Big cases on each adapter. They reuse the three native and eight
guest linkage/firmware/transport profiles. The same strict source, compiler,
executable and actual-ISO readers select the PMTU packet decoder and serialized
negative controls. The existing TCP loss job retains both complete PMTU evidence
directories in addition to its original loss and congestion coverage; the job
count and all original deadlines remain unchanged. These global-address tests
qualify the initial PTB ownership and metric subset. Scoped TCP, ordinary
ICMPv6 errors, cache expiry and full source/route/device lifetime acceptance
remain open.

Run the full test suite:

```sh
make test
```

The harness boots QEMU under BIOS and UEFI, checks firmware identity, requires every userspace marker, and checks the guest's explicit exit status. Fault diagnostics and failed assertions reject a run. QEMU exit code 1 represents guest success through `isa-debug-exit`.

CI builds the source and both userspace profiles once. Its 180 required jobs comprise one build, one storage admission job, 91 general tests, five downloads, sixteen persistent administration jobs, 32 administration fault jobs, 32 rotation jobs and two aggregate checks. Each rotation job runs its basic and expiry profiles in separate steps and evidence directories; an earlier scenario failure does not skip the later scenario or make the job pass. Each rotation profile uses one observed baseline and exercises every selected write/flush target in all three fault modes; the complete matrix retains all 3,840 fault cases. Journal verification runs in its own job, with four additional firmware/transport jobs for interrupted open-description recovery. Each rotation job keeps its existing 75-minute limit and preserves the complete storage coverage. The [complete TCP wire profiles](ci-tcp-profiles.md) run in seven jobs with their native/VM matrices and independent capture checks. The quoted-ICMP job includes [PMTU recovery](tcp.md#path-mtu-recovery) and native packet receive-buffer comparisons, plus [connection pressure and complete TIME-WAIT expiry](tcp.md#connection-pressure-and-expiry). [Full default TCP lifetimes](tcp-default-lifetime.md) add five jobs with concurrent native linkages and paired guest linkages, retaining complete default intervals and independent positive/negative evidence. Protocol and carrier jobs each run static and dynamic musl concurrently in independent source/build workspaces. Normal-init jobs pair modern and legacy transports in the same isolated process/workspace runner, retaining every RAM/ext2 and supervision scenario. Both normal workers begin with identical prepared kernel and root inputs. Each QEMU instance retains the original scenarios, packet verification and deadlines. Both workers must pass. Their separate logs and packet/results files are retained under `build/paired-network/<suite>/<linkage>/`, with a combined `results.json`; either worker failure rejects the aggregate gate. `python3 scripts/tests/paired_network_test.py` checks actual concurrency, workspace isolation, failure propagation and retained evidence.

Normal worker results and original fixture hashes are recorded in `build/paired-network/normal-init-<firmware>/results.json`. New fixture trees move intact to `build/normal-init-workers/<suite>/<transport>/`; only byte-identical top-level image/seed aliases are removed. The root-fixture artifact retains all worker ISOs. The authenticated fixture artifact retains inputs, initramfs archives, seeds, saved disks, screenshots and packet data. A retention collision preserves the original failed outputs in an explicitly unverified archive and fails the suite. Preserved temporary worker outputs stay under `build/ci-normal-workers/`; artifact paths retain their original fixtures and reports while excluding restored toolchain caches. Pre-existing checkpoints remain in place. Installed normal-init fixtures keep ordinary automatic IPv6 configuration enabled. `scripts/normal_ipv6_peer.py` validates complete default link-local DAD and router solicitations: guest/source/target identities, multicast destinations, hop limit, checksum, lengths and options. It retains the IPv4/DNS checks and rejects other IPv6 traffic. Each case stores original control frames and host observation times in `-ipv6-packets.json`; these records do not establish native packet-clock acceptance. Eight peer tests cover real captured frames, checksum-valid field damage, malformed firmware traffic, bounded capture and held DHCP acknowledgments. A complete local fixture replay passes all 32 RAM/ext2, BIOS/UEFI, modern/legacy and supervision cases with unchanged published guest images, kernel, observer and seed. Independent inspection reopens eight images, 64 screenshots and sixteen retained disks; current-kernel hosted qualification remains required.

Twenty-five account jobs cover native Linux comparisons, both target libc providers and linkages, persistent generation transactions, authentication, console/frontends, terminal and process primitives, record-lock lifetimes, journal rotation and normal graphical recovery. Four record-lock and four rotation jobs divide firmware/transport cells while retaining every RAM/ext2 case and reboot. The rotation suite distinguishes wrapped native publication faults from unwrapped guest operations and clean reboots; only its BIOS/modern job also runs the unchanged 32 MiB policy boundary. These checks retain complete source, executable, disk, filesystem, log and capture evidence after failures. Full current-revision CI and the remaining account acceptance requirements must pass before integration.

Native account commands and shells use root-owned Linux fixtures. Copied executables and libraries retain their original hash bindings; ordinary-user tests execute these copies from accessible fixture paths.

Three [resource-limit jobs](resource-limits.md) cover six native libc/linkage profiles, eight RAM guests and sixteen ext2 guests across both firmware modes and virtio transports. They exercise actual quota failures, signals, reclamation, stack-dependent exec budgets and simultaneous ordinary-user isolation under pressure. The healthy worker must retain its limits and keep working after the pressure worker is terminated. Persistent checks inspect its real file bytes and ownership. Every job retains its exact sources, logs, binaries and image/disk evidence, including failures. The native job also retains authenticated corresponding Ubuntu glibc source. Ordinary-user native exec controls use copied binaries and loaders in accessible temporary fixtures. Process-limit policy and exported-source compilation checks run during the build.

Twelve additional [randomness and cryptographic-client jobs](random.md) retain complete administration, virtio source, VM memory restore, seed ownership/rotation, actual disk-failure, interrupted-VM recovery, native ext2 process-crash, calendar/inventory, TLS/key/signature and ordinary-init matrices. Four seed jobs select BIOS/UEFI and modern/legacy transport while retaining both musl linkages and every crash/fault case. Real CPU and virtio reseeding intervals remain unchanged. Each job retains its actual inputs, images, disks, logs and results in an `axiom64-random-*-evidence` artifact, including partial failures. OpenSSL builds once against both target providers and native Linux; jobs reuse checked staged products. The shared input archive omits its extracted upstream source cache, intermediate objects/archives and unused upstream test/fuzz executables while retaining every manifest product and generated configuration header. Corresponding upstream sources and signatures remain in the separate source artifact.

Run `python3 scripts/tests/random_crypto_wait_observer_test.py` for the cryptographic initialization observer protocol. Real subprocesses and the native monotonic clock check an early guest marker, a host delay after serial delivery, premature completion, a failed client and missing release confirmation. These protocol checks run within the existing cryptographic guest steps. Actual OpenSSL acceptance still requires the complete native and guest clients, both half-second observations, zero-credit/pending/output checks, original images and recorded inputs.

Physical PCI removal in the carrier fixture pauses the guest and preserves its configuration-address register before resuming it. A guest stopped between its address write and data read must still read the selected device. `python3 scripts/tests/manager_link_hardware_test.py` checks this behavior for both adapters and transports, including failed removal verification.

The disabled-profile removal observer waits for an actual raw-descriptor EIO even
when the profile already has no address, route or active carrier. It retains the
five-second observation bound. Active managers must also report their own EIO;
a saved-disabled profile does not require an event from an inactive manager.
The static BIOS legacy lane-zero case holds the real guest after receiving the
complete `down` command, removes the selected PCI adapter, then resumes command
evaluation with its capture flag still clear. The observer must obtain EIO from
the actual descriptor before accepting the down state. This regression uses a
verified executable boundary and changes no guest memory, registers or clocks.
Its source snapshot, actual ISO, embedded kernel/initramfs/programs, debugger
commands, original state and removal receipts remain in
`build/manager-link-removal-evidence/`, including failures. Hardware removal
restores the PCI selector while held and resumes on failed verification. The
existing profile count, healthy-adapter renewal and teardown checks remain.


Normal desktop acceptance drives private administrator creation and login through the installed console, then checks the ordinary session before sending the X11 command. The console driver waits for Bash to return its prompt before sending the next command. Its `printf` acknowledgements contain no complete marker in their input echo. Interleaved console output therefore cannot turn echoed command text into a completion acknowledgement. The host ends the boot only after the window manager, mapped terminal, keyboard acknowledgement, input injection and captured screenshot have all completed. Disk-root shutdown uses authenticated sudo. `python3 scripts/tests/desktop_console_test.py` replays premature acknowledgements, missing readiness, failed identity and actual generated shell output; `python3 scripts/tests/normal_login_test.py` checks split prompts, private elevation input and command return ordering. The BIOS/UEFI boots still exercise the real X11 probe and keyboard/mouse paths.

| Test | Evidence |
| --- | --- |
| Static and dynamic musl ABI | Files, hard links and unlink lifetime, directories, isolation, fork/exec/wait, mappings, pipes, descriptors |
| Threads and futexes | Static/dynamic musl lifecycle, TLS/FPU, shared resources, mutex/condition/semaphore contention and timeouts, bitset/requeue, mapping lifetime, cross-process wake, worker fork/exec, and group teardown |
| Blocking I/O | Static/dynamic retained descriptions across close/dup2/reuse, captured vectors, socket transfers/accept, finite Linux socket deadlines across four families, expiry after buffer unmap and readable copy faults, nested/restarted/abandoned signal contexts, errors, failed/successful exec, and endpoint/resource cleanup; matching native Linux comparisons. The vector client adds 77 metadata, 24 read-copy, 20 write-copy, 16 empty-send/signal and 18 cross-vector chunk cases, including a glibc native comparison |
| IPC | Unix sockets, edge and one-shot epoll, batches of 256 events, select/pselect, anonymous/file/SysV shared memory |
| Signals | Masks, alternate stacks, return frames, interrupted and restarted I/O, caught faults, SIGCHLD, alarms, stop/continue |
| Credentials and permissions | Sanitized policy/allocation/lifetime checks; three native Linux clients; eight static/dynamic BIOS/UEFI RAM/ext2 kernels; real users, privilege-dropped exec, capabilities, chroot, mount policy, signal/network/IPC guards and independent persistent-owner checks |
| Xattrs and file capabilities | Sanitized allocation, wire and EA codecs; three native libc profiles on tmpfs/ext2; actual maintained getcap/setcap tools; BIOS/UEFI and both virtio transports; RAM/ext2 exec, fresh kernel boots, independent EA/ELF exports, shared-block lifetime, malformed disks, disk exhaustion and deliberate I/O faults; independent receipt/ISO/metadata audit and damaged-evidence rejection |
| Elapsed clocks | Sanitized counter arithmetic/ACPI parsing, 24 firmware/transport/HPET-TSC/delay boots, independently timed flushes, and absolute futex/interval-timer deadlines across storage |
| Advisory file locks | GNU sanitizer and static/dynamic musl native comparisons, four guest RAM/ext2 boots, deterministic traces, retained waits, lifecycle, contention, read-only mounts and host fsck |
| PTYs and authenticated sessions | Existing IPC controls plus six-native/eight-guest private ownership/lock/takeover/hangup/lifetime checks, raw-device denials, quiet password entry/cancellation, and two actual ordinary shells with identity/group/terminal/file/process checks, exact output, logout and supervisor-failure cleanup; full account integration remains in [account and login support](accounts.md) |
| Password cancellation at the wait boundary | `scripts/account_secret_test.py` keeps the original input/EOF/signal controls and injects a real ignored SIGHUP immediately before the reader waits. Native and guest clients require cancellation without another input byte, cleared secrets and restored terminal attributes, descriptor flags, signal actions and signal mask |
| Account frontends and login journals | `scripts/account_access_test.py`, `account_logbook_test.py` and `account_session_test.py` run real private provisioning/login/su/sudo/passwd, forced changes, redirected streams, generation checks, supervisor leases/recovery and a pinned portable GNU utmp reader; rotation checks add retained active sessions, four closed archives and exact independently decoded projections |
| Child events, process identity and exec | Six native profiles and BIOS/UEFI guest matrices verify waitid/WNOWAIT, actual process/thread birth, secure boot UUIDs and unready errors, long argument/environment input, checked stack construction and failed-exec state; host serializers/capture code run under sanitizers |
| POSIX and OFD record-lock lifetime | Native comparisons and 48 RAM/ext2 boot phases verify deadlocks, restart/signal/stop/continue/fatal cleanup, exec, descriptor replacement, inode aliases, exhaustion rollback, exact disk bytes and independent filesystem checks |
| Process status and account-use checks | `scripts/proc_test.py` compares six native and eight guest profiles for all identity fields, thread lookup, buffered/unread exit behavior, 256 task-slot recycles, complete 65,536-group reads and failed procfs inspection; live shell tests run actual administrative commands under the database/logbook guard |
| First-boot console and aliases | `scripts/account_console_test.py` runs private administrator creation, required login, restart/logout, worker metadata denial, killed-reader reset and damaged-store refusal; frontend tests execute actual login/su/sudo/passwd aliases. Normal-image installation and persistent reboot remain separate requirements |
| Terminal input flushing | `scripts/terminal_flush_test.py` compares six native and eight guest profiles for TCSETSF/TCFLSH, both PTY endpoints, already received output, invalid selectors and fault atomicity, with an additional GNU ASAN/UBSAN client |
| BusyBox, Bash, zsh | Real shells, substitutions, pipelines, filesystem commands, exit statuses |
| Native GNU tools | Guest compiler, assembler, linker, Make, executed C/C++ results, C++ threads and condition timeouts, standard library, exceptions, rejected-source diagnostics |
| X11 | Real Xorg, drawing/GetImage comparisons, physical framebuffer pixels, twm ownership, mapped xterm with text |
| Desktop input | QEMU PS/2 mouse and keyboard; a command typed into interactive Bash creates a file checked by the guest |
| Virtio storage | Separate 16-boot firmware/transport matrix, host disk-byte comparison, fresh-boot persistence, read-only disks, index rollover, backend read/write/flush errors |
| Shared virtio queues | Sanitizer host simulation, concurrent chains and malformed completions; separate 24-boot real queue-size/feature matrix with host byte checks |
| Ethernet and packet sockets | 46 boots covering both NICs, firmware/transports, queue sizes, eight interfaces, rollover, link transitions, optional features, malformed completions, TX backpressure, raw socket behavior, and host byte comparisons |
| IPv4, ARP, and raw ICMP | Eight mixed-NIC boots covering firmware/transports, loopback, static configuration/routes, cache expiry/replacement, malformed input, link loss, bounded queues, retained descriptions, kernel echo/errors, BusyBox ping, and isolated device failure |
| IPv4 fragment ownership | Production reassembly and fragment emission under ASan/UBSan; six receive and twenty-one output wire cases per adapter, raw ICMP/UDP, minimum MTU and maximum datagrams, discovery policies and privileged quota denial. Glibc/static/dynamic Linux TAP comparisons retain independent captures and zero-drop receipts. Real 60-second expiry checks retain exact quotes, duplicate timing, staggered suppression and identity reuse on both NICs. Mutation checks preserve unrelated packets with colliding IPv4 IDs; broader transport acceptance remains required |
| IPv4 path MTU | Production bounded shared cache under both sanitizers; eighteen cases per NIC with all six policies, exact raw/UDP bytes, cross-protocol queries, invalid hints, floor locking and independent raw observers. Separate capture audits require sixteen damaged fixtures per NIC to fail. |
| IPv4 path MTU lifetime | Both NICs age concurrently through the complete 600-second limit, with original and fresh DO sockets, repeated nonrenewing lookups, invalid/valid quotes and exact post-expiry datagrams. Independent original-clock audits require sixteen damaged fixtures per NIC to fail. |
| IPv4 gateway routing | Three native linkages and eight static/dynamic guest profiles exercise distinct gateway MACs, direct fallback, bound source aliases, route replacement and shared raw/UDP cache lifetime. Each process or boot also checks fourteen fresh and 110 retained-source datagrams per NIC using Ethernet barriers. Independent capture audits require twenty-two gateway and 31 unconfigured-output controls per NIC to fail. |
| IPv4 UDP | Eight mixed-NIC boots covering firmware/transports, native Linux comparisons, datagram boundaries, checksums and malformed input, client/server traffic, reuse and broadcast, queue pressure, retained I/O, signals, fork, link changes, and isolated device failure |
| TCP malformed inputs | Three native linkages and eight mixed-NIC guest boots; seven actual checksum/option injections per adapter with complete recovery waits, exact 16-byte requests and 112-byte replies, both acknowledged FINs, independent packet/clock/source/runtime checks, inspection of both boot images and 220 rejected capture copies |
| TCP congestion and receive windows | RTO and duplicate-ACK peers each exercise three native linkages and eight mixed-NIC guest boots; opening/growth, two actual RTOs, oldest-byte fast retransmit, inflation/deflation, 1024-byte receive ownership, exact 65536/16-byte streams and acknowledged FINs; independent flight/clock/input/image audits and 198/242 rejected capture copies |
| TCP quoted ICMP errors | Three native linkages and eight mixed-NIC guest boots; 57 cases per NIC, 128 descriptor reuses, emitted sequence/tuple ownership, hard and soft errors, retained/interrupted calls, ACK recovery, passive requests, TIME_WAIT and live unrelated streams/listeners. Fixed passive listeners bind before active connections; native attempts to take those ports must fail. Independent packet/receipt/clock checks and 242 synchronized damaged fixtures |
| TCP PMTU recovery | Three native linkages and eight mixed-NIC guest boots; 12 independent paths per NIC, active/passive opens, legacy and consecutive reductions, eight damaged/unowned/nonreducing controls, exact 4096-byte streams each way and acknowledged close; independent original-packet, driver-receipt, zero-drop and source/product checks |
| TCP connection pressure | Three native linkages and eight mixed-NIC guest boots; 5120 listener/child teardown cycles, 2560 refused/aborted attempts, compact-table saturation, live TCP companions and 32 fresh UDP endpoints, complete 120-second expiry and repeated recovery; original packet/driver/clock/input checks and 198 damaged-evidence controls |
| TCP disconnect/reconnect | Three native linkages and eight mixed-NIC guest boots; six cases per NIC covering same-description abort reuse, completed tuple guards, independent destinations, retained queued output and an A-to-B-to-A revisit; exact original and successor streams, wrapped peer sequences, owned resets and acknowledged FINs; 471 packet, queue, observer, result, source and cohort mutations. The client waits eleven full seconds using nanosecond elapsed time; ARM observations precede client release. Host clock and observer regression checks run in the build policy job. |
| TCP interface recovery | Three native linkages and eight mixed-NIC guest boots compare administrative down/up before enqueue, confirmed output holds, full 4500-millisecond holds with actual guest IPv4 copy expiry, connected-route withdrawal, explicit host-route deletion and physical carrier loss on each NIC. Route cases confirm fresh-connect failure and undelivered buffered bytes before restoration. Each stream preserves 6224 exact bytes and four control bytes, with live companion traffic. Independent reconstruction checks bytes, ACKs, controls, close and actual queue, expiry, route and carrier observations; 513 damaged packet, queue, expiry, route, carrier, result, source and cohort cases must be rejected. Guest output-boundary observations remain separate from retransmission timing acceptance. Wider route-policy cases remain required. |
| TCP permanent device loss | Both adapter selections across three native linkages and all eight guest configurations: six private native-netdevice deletions and sixteen actual guest PCI removals with owned 512-byte output, error readiness and syscall progression, exact reclamation and live original companion streams for 5000 milliseconds; 44 independently checked captures, four opened boot images and 284 rejected damaged-evidence controls. Native configured deadlines and guest default TCP behavior retain their separate contracts. See [device-loss acceptance](tcp-device-loss.md). |
| IPv4 netlink routes | Four mixed-NIC boots, native Linux namespace comparison, sanitized message fixtures/mutations, tagged ownership and unrelated-route preservation, actual routed packets, descriptor lifetime, malformed requests, and route/socket/reply quotas |
| IPv4 address/configuration | Four mixed-NIC boots, native address-message comparison, sanitized parser fixtures/mutations, complete tuples, owned replacement/recovery, manual preservation, malformed journals, publication failure, six partial intents, and actual route-quota rollback |
| DHCP modules | Twelve codec/state/profile boots plus four independently checked real-wire acquisition/renewal/rebinding/release boots |
| Network manager | 104 actual-process boots with both NICs and musl linkages across firmware/transports: independent DHCP, saved overrides, static conflicts, manual preservation, singleton rejection, killed-process restart, and publication/teardown failure recovery |
| Private saved network files | Native GNU sanitizer and static/dynamic musl under ordinary/root UIDs, real foreign owners, writerless FIFOs and atomic publication failures; eight static/dynamic guest RAM/ext2 boots with ABI checks, unmount, seed preservation and host fsck |
| Resolver metadata | Native sanitizer checks and four guest boots for bounded eight-interface merging, complete search names, manual preservation, permissions, ownership/intent recovery, checked publication failures, and resource retry |
| VFS mounts | Independent RAM volumes, hidden/restored contents, directory identity, read-only policy, cross-filesystem errors, executable loading, mappings, sockets, busy unmounts, slot reuse |
| Writable ext2 | Four disk layouts across firmware/transports, guest files and executable loading, fresh-boot reads, host file/metadata comparisons and fsck, full allocation, rejected formats, I/O retries, checked free-counter reconciliation and structural rejection |
| Checked deleted-inode recovery | Six retained interrupted volumes and generated controls across four layouts and both firmware/virtio paths; 252 boots verify whole-volume contents and identities, file/symlink/empty-directory link restoration, bounded parent correction, strict post-recovery fsck, unchanged rejected disks, shared EA ownership, ancestry and 70 retired inodes in one mount |
| Linux path descriptors | Six native profiles and 32 RAM/ext2 guest cells retain all original 60 observations, with POSIX lock-close controls for 71 each and four additional mounted-device checks on ext2; retained fixtures, strict filesystem checks and actual process-group cancellation |
| Internal JBD2 journals | Sanitizer crash/retry, stale-ID restart/wraparound and replay controls; four native Linux-created layouts with separate checker oracles; 128 read/write guest cells across both maintained musl providers, linkages, firmware paths and virtio transports; 32 more boots reject 144 unsupported, malformed or hardware-read-only volumes with unchanged bytes; source/product snapshots, retained interrupted disks and strict postchecks |
| Journaled open-description recovery | 128 actual VM kills while a regular file with indirect storage and an external attribute, a path-pinned symlink and an empty directory remain open; complete serial records bind the interruption boundary, with all partial records checked by `scripts/tests/journal_lifetime_boundary_test.py`; fresh writable/read-only boots reclaim storage and preserve seed bytes; 160 unchanged-volume denials across four layouts and both firmware/virtio paths; complete source/image/disk and counter evidence |
| Ext2 root | Root and data-volume reboot persistence, software/hardware read-only policy, rejected configuration/boot files/backend failures, full userspace and normal desktop startup across firmware/transports, reproducible fixtures and host fsck |

The native path-descriptor cancellation checks distinguish live children, unreaped zombies and children reaped while their procfs status is being read. Disappearance during open or read completes that observation; permission and other I/O errors still fail. Real process controls also retain process-group ownership checks during cleanup. The regression runs from exported corresponding sources as well as the checkout.

The host captures `build/desktop-bios.png` and `desktop-uefi.png` after input succeeds. Logs are `build/boot-bios.log` and `boot-uefi.log`; results are in `build/boot-results.json`.

CI can reuse completed musl and OpenSSL products across revisions with identical dependency locks, recipes, local patches and host build inputs. The cache key includes actual compiler/tool bytes, native linker inputs and C headers. It also binds the workspace path used by compiler specifications. Cache hits still run the maintained builders, complete product hash checks and damaged-input controls. The cache retains staged tools, libraries, notices, manifests, logs and generated configuration headers; it excludes OpenSSL source and intermediate object trees. Input fingerprints, product counts and cache-hit evidence accompany the account-policy artifact under `crypto-cache/`. Complete cold and warm workflow timings are needed before claiming an overall CI improvement.

Read these reports together: `inputs.json` records the exact key and build inputs, `cache-hit.txt` records whether the cache action found that key, and `products.json` records the completed manifests and verified product counts. An empty or `false` cache-hit value means a miss; `true` alone does not prove that restored products passed verification. Compare successful complete workflows with matching build inputs, including queue time and the unchanged guest jobs. Documentation changes can reuse the key because they do not change a dependency recipe or product.

Artifact downloads use a pinned Node 24 action and reject digest mismatches before restored inputs reach tests. Native file-capability comparisons obtain Ubuntu source indices through the content hash in a signature-verified Release. This avoids combining an older Release with a newly published mutable index. Capture retains rejected index bytes and their expected/actual hashes under `archive-authentication/`; a failed transfer never becomes a completed index cache entry. Verified public indices use mode `0644`, so ordinary CI readers and uploaders can read files produced by root. Twelve HTTP regression cases cover publication identity, truncated responses, missing indices, damaged cached bytes and evidence-reader access. If a publishing mirror returns 404 for its hash path, one canonical-index request may supply the same bytes; its complete length and SHA-256 must still match the already signature-verified Release. Both request statuses remain recorded. A changed canonical index, other HTTP errors and damaged cached data remain failures. When run as root, the access case drops to an unprivileged UID to read the actual cached and copied files. The extracted-source checks run these cases too.

For shorter development loops:

```sh
python3 scripts/boot_test.py --suite abi --firmware bios --timeout 60
python3 scripts/boot_test.py --suite desktop --firmware bios --timeout 120
python3 scripts/boot_test.py --suite threads --phase cond --firmware both --timeout 30
make test-thread-io
python3 scripts/boot_test.py --interactive --firmware both --timeout 180
python3 scripts/storage_test.py --firmware bios --transport modern
make test-virtqueue
python3 scripts/virtio_test.py --firmware bios --transport modern
python3 scripts/ext2_test.py --quick --firmware bios --transport modern
python3 scripts/network_test.py --firmware bios --models virtio e1000
python3 scripts/ipv4_test.py --firmware bios --transport modern
python3 scripts/udp_test.py --firmware bios --transport modern
python3 scripts/netlink_test.py --firmware bios --transport modern
python3 scripts/configuration_test.py --firmware bios --transport modern
python3 scripts/dhcp_modules_test.py --suite state --firmware bios --transport modern
python3 scripts/profile_test.py --volume ext2 --firmware bios --transport modern
python3 scripts/dhcp_transport_test.py --firmware bios --transport modern
```

The ABI, desktop, condition-only, and I/O-only profiles omit large native development packages from a separate root filesystem. The full and complete threads suites use the full root filesystem. `--trace` logs syscall entry and results; `--gdb` exposes QEMU debugging on local TCP port 1234.

GitHub Actions builds the normal ISO, both userspace profiles, and test clients once, then runs 42 non-TCP test jobs, ordinary TCP, seven controlled TCP profiles and five default-lifetime jobs on Ubuntu 24.04. Six cover boot/threads/queue geometry/desktop; Ethernet/IPv4/UDP/netlink; configuration/DHCP/resolver/clocks/file locks; raw storage/ext2; root/data persistence and delayed I/O; and full userspace/desktop from ext2 root. Four manager jobs each run both musl linkages for one BIOS/UEFI modern/legacy combination. One job checks randomness and saved manager hints, two check normal init supervision by firmware, and one compares credentials with Linux and exercises guest permissions. Eight protocol jobs each select a firmware, virtio transport and affected adapter, and run both musl linkages in separate workspaces. Together they run all 272 protocol cases, including lease timers and packet checks. Eight carrier jobs use the same dimensions for all 320 carrier and adapter-failure cases. All firmware, transport, sanitizer, native Linux comparisons, host fsck, and [disk-root checks](disk-root.md#verification) remain required. Harnesses sharing generated image paths run sequentially within a workspace. The final `qemu` check fails if the build or any test job fails, is cancelled, or is skipped.

The hosted workflow checks proposed changes, updates to `main`, tags and manual runs. Newer runs on the same ref cancel earlier ones; feature checks avoid duplicate builds for the same update. Dependency and source archives are cached by the three lock files, and the fetchers verify their recorded hashes. Compiled outputs are shared only within the current run, with source timestamps and executable modes preserved together in a temporary archive. The build job uses the canonical Ubuntu HTTPS archive and Ubuntu archive keyring for its initial metadata refresh, common tools and formatter. CI package operations skip translated package-description indexes through the documented [APT language setting](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html). It retains the downloaded common-tool packages, their SHA-256 hashes, and installed versions. Test jobs verify those hashes and install the shared packages without downloading them again. If local installation needs updated repository metadata or extra runner dependencies, Ubuntu jobs use the same signed HTTPS repository to install the explicit package list. Other distributions retain their configured repositories. The installer seeds APT's archive cache with the verified bundle so this fallback only downloads packages absent from it. Each APT command has a ten-minute limit, a thirty-second kill grace, thirty-second HTTP/HTTPS timeouts and a sixty-second package-lock limit. A failed refresh or installation fails the job; these limits apply to tool setup and preserve the guest observation deadlines.

Tool installation uses explicit packages without optional recommendations. Only the build job installs clang-format and checks formatting; test jobs reuse the checked sources without downloading the formatter and its LLVM libraries. QEMU runs headless and desktop screenshots come from QMP. The `axiom64-boot` artifact contains the normal image, kernel, and build log. The `axiom64-evidence-*` artifacts contain each job's logs, results, traces, screenshots, and host dumps, including evidence from failed tests. Paired protocol and carrier artifacts retain each linkage's logs and reports in separate directories. `axiom64-disk-root` contains the full root image and boot copies; `axiom64-credentials-fixtures` contains permission-test disk and boot images. `axiom64-sources` carries upstream archives and exact package recipes. `axiom64-ci-inputs` is the internal build archive and expires after one day. A green run applies to its tested commit; check that commit when comparing results with local changes.

Administration clean/fault jobs and their coverage aggregate reuse `axiom64-ci-rotation-inputs`. This focused archive retains their source and prepared build inputs while omitting unrelated curl/OpenSSL products and normal root images. It also omits completed GNU reader control copies, ext2 codec disk fixtures, unrelated guest compiler/desktop packages and curl/OpenSSL source downloads. The pinned Linux UAPI package, prepared libc/password products, source, build-tool bundle and boot inputs remain available. The complete input profile retains those downloads and controls. An exact published 414,251,141-byte archive passes the previously cancelled runtime/dynamic/UEFI/legacy/writethrough fault cell locally: nine observed targets across all three fault modes, 29 total phases in 26 minutes 9 seconds, and its coverage index. The same input set also passes that profile's clean and storage controls. All sixteen clean, thirty-two administration-fault and sixty-four rotation profiles retain their commands, coverage and deadlines. The two rotation scenarios share each of thirty-two jobs' input restoration and tool setup. Complete hosted acceptance and a full before/after runtime comparison remain required.

A subsequent local correction retains an automatically selected source after socket output has been admitted and copied. If that address is removed or expires while output waits, the copied packet keeps its original source while a usable route remains. Pending neighbor resolution chooses another usable local source without renewing its attempts or deadlines. Host regressions cover both adapters, explicit deletion, finite expiry, final close/reuse and source withdrawal during raw fragment submission. Actual Linux 6/7 probes and one static BIOS/modern guest cover four UDP and four fragmented raw observations, with fresh companion controls. Independent inspection reopens twelve captures and rejects 144 serialized changed controls. The public host client now appends sixteen queued-output cases to every original host and lifetime phase: both adapters, UDP and 4,000-byte fragmented raw output, deletion or finite expiry, and live or finally closed/reused descriptors. The finite cases retain one-second preferred/valid lifetimes, sample at 1.1 seconds and require actual absence within 2.5 seconds. Their original packet clocks must still show at least one second before withdrawal. Creation and selected-source neighbor barriers precede removal; delayed resolution and completion acknowledgments require the exact copied output, then fresh companion-source traffic. The complete source-bound Linux 7 client passes all sixteen new cases while preserving all 58 address rows, six source queries, eighteen lifetime exchanges and four expired-input barriers. Every actual client/image/log/capture is checked before binding the reference. All eight current guest profiles pass in 33.6ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“39.9 seconds against the unchanged 45-second deadline. Independent current readers reopen their sixteen captures and reject 240 serialized queued-output controls, including excess neighbor probes. The reference captures reject another thirty controls. The new workload includes its original native capture-bracket and reader-latency gates; a separate regression uses real packet bytes/timestamps and synthetic receipts to reject a 1,501-millisecond queued-reader delay. Those controlled receipts do not establish native timing. All three current native clients complete all sixteen cases with unchanged inputs and zero drops, but all original stable clock-offset gates fail and remain excluded. The eleven-profile local ABI comparison passes and rejects 198 changed logs without qualifying packet timing. Current-source native packet-clock qualification, complete hosted acceptance and broader retained-call/route/cache behavior remain required.

Run `make test-storage` for the complete disk matrix. The harness creates and overwrites only its generated fixtures under `build/`. [Storage verification](storage.md#verification) describes the phases, host comparisons, evidence files, and paths that are not yet fault-injected.

Run `make test-ext2` for the complete filesystem matrix. [Ext2 verification](ext2.md#verification) describes supported layouts, host `debugfs`/`e2fsck` checks, failure injection, and remaining limits. The harness creates its own disk images under `build/` and accepts no user disk path.

Run `make test-threads` for the dedicated static/dynamic musl, futex, lifecycle, and guest-compiled C++ suite. [Thread verification](threads.md#verification) describes coverage and evidence files; complete POSIX threading and SMP remain planned.

Run `make test-thread-io` for the focused [blocking I/O suite](io.md#verification-and-limits). The full and complete thread suites also require its static/dynamic tests.

Run `make test-virtqueue` and `make test-virtio` for the [shared virtio queue and transport checks](virtio.md#verification). The host simulation exercises production queue logic with sanitizers; actual guest runs cover register access, negotiated geometry, disk payloads, and persistence.

Run `make test-disk-root` for the [root and data-volume persistence/rejection matrix](disk-root.md#verification). Full and normal desktop boot tests accept `--disk-root --transport modern` or `legacy`; they build a matching root fixture, copy it for each firmware boot, require the selected ext2 root, perform clean shutdown, and run host fsck.

Run `make test-network` for the complete [Ethernet and packet-socket matrix](network.md#verification). Each NIC communicates with its own loopback peer; fault and backpressure cases use a local GDB session. Results accumulate in `build/network-results.json`, and CI retains logs and debugger commands. Dedicated pressure trials write and verify the selected link's IPv6-disabled precondition before activation, retaining every transmit slot, EAGAIN/readiness check and completion wakeup. The complete local 46-case matrix passes; independent readers reopen 34 distinct images and reject 164 changed serial logs. Normal cases require actual administrative-down flags `1002`; the old expectation that RUNNING remains set was corrected to match Linux. `python3 scripts/tests/packet_administrative_test.py -v` checks the actual C helper against the accepted flags and four rejected alternatives. CI also retains the active Ethernet image, initramfs, packet client and fixture source for independent inspection.

Run `make test-ipv6-configuration` for twelve actual configuration-ABI guest profiles: static/dynamic linkage, BIOS/UEFI, and modern virtio, legacy virtio or e1000. Each compares all 105 scalar/vector, offset, permission, truncation, stable-secret and address-limit records with the measured Linux 7 fixture. The original 86 rows remain unchanged. New records cover per-interface/all/default scope, signed bounds, zero and negative limits; all three native linkages also match on Linux 6.17. The two images are reopened against their actual kernel, program, loader, source and boot script. `sudo -n make test-ipv6-configuration-native` compares three Linux linkages in private mount, PID and network namespaces; it never changes the host's interfaces. `python3 scripts/tests/ipv6_configuration_test.py` rejects damaged observation logs. These checks cover configuration I/O, not RS/RA/SLAAC or packet-clock acceptance.

`make test-ipv6-link-configuration` and `sudo -n make test-ipv6-link-configuration-native` use the same guest and native dimensions for 39 netlink generation-mode and link-query records. The observation reader also rejects damaged mode, error, query and completion records. `make test-ipv6-socket-configuration` and its `-native` target add 63 device-binding and legacy/modern hop-limit observations per profile, including protected name buffers, ordinary-user changes, shared descriptions, truncated controls and ICMPv6 error queues. The client decodes Linux x86-64 control headers directly so libc iterator differences cannot hide a final truncated header. Fifteen local socket profiles match 945 observations; independent readers reopen two actual images and reject 75 serialized damaged logs. CI runs these configuration matrices in the existing configuration job and retains their complete inputs and products in the `ipv6-configuration` artifact. The network job retains its packet and timing cohorts. IPv4 UDP, DHCP transport and manager packet fixtures explicitly select manual IPv6 generation before bringing their IPv4 interfaces up. Their strict IPv4 peers, packet requirements, timers and ordinary system defaults retain their existing behavior. The route-control fixture disables IPv6 before its IPv4-only client starts.

The link-configuration targets also require `make test-ipv6-configuration-lifetime` and its `-native` counterpart. The shared C client records 564 observations for administrative shutdown and MTU retirement on both interfaces. Fresh paths, retained control and directory descriptions, scalar zero-length reads, invalid writes, `fstat`, new inode identity and current default inheritance must match the selected measured Linux reference. Restoring MTU cannot revive a retired description. All twelve local guests pass 6,768 records, with two images and 96 archived damaged logs independently checked. All three actual native linkages complete on both pinned Linux kernels. Their eight malformed `disable_ipv6` write differences remain explicit in separate fixtures; unaudited native releases fail before execution. These checks cover configuration I/O. DAD wire clocks and device-lifecycle packet acceptance remain separate requirements. CI retains both lifetime output directories in the existing artifact and adds no jobs.

`make test-ipv6-router` runs the controlled [router and SLAAC subset](ipv6.md) across twelve guest profiles; `sudo -n make test-ipv6-router-native` runs three isolated Linux libc profiles. Both interfaces carry the selected NIC model. Two VM workers preserve each sixty-second deadline and every packet/lifetime scenario. Captures must retain four-second router and eight-second address lifetimes; the two-hour check queries the protected remaining lifetime rather than claiming a two-hour expiry observation. Native captures require complete software checksums, zero packet drops, original kernel timestamps, one stable realtime-to-monotonic translation and the existing reader-latency bound. A failed clock gate keeps the profile unaccepted even when its application succeeds. The existing configuration job retains all router inputs, programs, images, logs, offload settings, captures and clock receipts. `python3 scripts/tests/ipv6_router_capture_test.py` reopens actual QEMU evidence and rejects missing/truncated packets, invalid snapshot bounds, changed hops/lifetimes, shortened expiry observations and missing policy records. The expanded client adds six states per interface: netlink replacement, zero-lifetime PIO, finite-lifetime refresh, explicit removal/readdition and both PIO updates again. It requires matching address flags, preferred/valid caches and exactly one permanent connected route. All twelve current guest profiles and the complete source-bound Linux 7 VM pass; independent readers reopen both images and all 24 guest captures. The twenty-seven-phase client retains distinct two- and three-second RA retransmission values. The peer withholds each first neighbor answer and requires the correctly timed second solicitation before releasing the queued UDP exchange. Fifteen replay tests reject missing replacement/readdition and first-PIO records, lost flags, duplicate or nonpermanent prefixes, unchanged infinite lifetimes after readdition, checksum-correct damaged PIO or timer fields, a missing retry and the original one-second retry bug. All twelve guest profiles and the same source-bound Linux 7 client pass every phase. All three current native clients qualify both original clocks with zero drops; independent readers reopen their six original captures. The preceding seventeen-phase dynamic-musl and glibc clock failures remain excluded.

Four new phases configure permanent and finite addresses under fresh A-only and A+L prefixes before their first PIO. A zero advertisement and subsequent finite refresh must produce twelve complete state observations per interface, including exact final flags, protected caches and configured connected-prefix metadata. The same executable passes on Linux 7, all twelve guests and all three native libc profiles.

The appended cross-interface phase installs distinct 41/51-hop defaults and requires echo and port-error replies to use the outgoing interface. Every original echo byte and quoted datagram must match. 150 serialized damaged captures across all thirty current positive captures reject wrong hops, changed quotes, missing replies, changed first-zero lifetimes and missing first-PIO phases. The client observes a measured Linux deprecation-bit delay for at most one second, while requiring every other address/cache/prefix field immediately and the exact final flags. Manual netlink replacements keep their immediate checks. The sixty-second profile deadline and all original wire/clock gates remain intact. The preceding forty-five-profile configuration campaign passed 2,820 records, six reopened images and 165 serialized changed logs. The expanded address-limit kernel passes all 36 configuration guests, retaining the original observations and adding the new quota records: 2,484 records, six reopened images and 168 changed logs. Its twelve router and twelve DAD guest regressions pass, with four images and 48 captures independently reopened. Complete current-revision hosted acceptance remains required. Earlier reader, flag and clock failures remain retained.

`python3 scripts/ipv6_dad_test.py --directory build/ipv6-dad-wire` checks stable recovery with real UDP, four-trial A-only and A+L exhaustion, one-trial EUI-64 failure, retained failed permanent configuration and three-probe regeneration with copied lifetimes. Its twelve guests cover both linkages, firmware types and all three NIC models, with two workers and the original sixty-second profile deadline. `sudo -n python3 scripts/ipv6_dad_test.py --native --directory build/ipv6-dad-native` runs the same client through three native linkages. Each interface must retain 31 ordered controls, fourteen distinct queried candidates, twelve valid conflicts, eighteen global probes and two link-local probes. A conflict requires both the actual probe and tentative metadata. Exhaustion retains a full three-second observation. Retry captures must measure at least one second and at most 2.1 seconds; original native timestamps, both clock checks and zero drops remain required. The current twelve guests and three native Linux 7 linkages pass. The preceding 999,710-microsecond guest retry and native clock/observer failures remain retained and unaccepted.

`make test-ipv6-ownership` runs the shared `ipv6_address_ownership.c` client in global, lifecycle, secret-change and capacity groups, retaining a separate sixty-second deadline per profile. Both static/dynamic linkages, BIOS/UEFI and modern/legacy/e1000 devices remain required, for 48 guest profiles. `sudo -n make test-ipv6-ownership-native` adds twelve isolated static, dynamic and glibc comparisons. `--group secret` selects the secret-change cases; `--group both` retains the original two groups and `--group all` selects all four. `--group capacity` selects the quota cases alone. The nine cases cover takeover, last-address cleanup, preserved permanent failures, generation-mode changes, four-trial exhaustion, raw six/ten-second cache cloning and finite ordinary/NODAD recreation. Every selected conflict follows a real matching probe and fresh queried flags/lifetimes; its packet precedes the ACK that starts the unchanged 4.1-second client wait. Native initial-DAD jitter is observed through actual completion, while the two/eight-second recreation input stays fixed. Both finite interface conflicts are sent from fresh queries before either ACK is awaited. A preferred-lifetime boundary can precede Linux publication of `DEPRECATED`; a timestamped inventory poll waits at most one second for the actual flag without changing the original lifetime input or expected final inventory. Secret changes are read back on the selected interface before conflict injection, including during link-local retry exhaustion. Readers require complete four-second quiet windows, exact inherited flags, natural cache aging, unchanged original native clock/latency checks and zero drops. Prefix cleanup is selected before execution with the existing audited release policy. Unknown or differently backported behavior fails until audited.

The original three retained ownership fixture groups reject 73 damaged controls. The new capacity fixture adds 36, including limit readbacks, both full quiet intervals, the actual raised-limit ACK, fresh PIO/DAD, permanent failures and manual bypass. The capacity client checks finite SLAAC removal at its actual per-interface limit and fresh-owner initialization only after a new advertisement; its permanent link-local case retains the failed owner and permits an explicit manual NODAD address. All 48 local ownership guests and twelve native profiles on each of Linux 6.17 and Linux 7 pass. Independent readers reopen eight images and all 144 original captures and reject 2,616 archived guest corruptions. The current finite manual-takeover case sends both freshly queried interface records before either conflict ACK wait, preserving the exact six/ten-second cache predicate. The complete corrected client passes all 48 guest and 24 native profiles; independent readers additionally reject 48 archived native packet-clock corruptions. Original failed executions remain failures. Receive-path sanitizer models also cover all sixteen occupied address slots, failed finite/permanent owners, secret and mode changes during retry holds, and carrier/admin/MTU restoration. Their eighteen combinations exercise production address state with explicit policy ticks; matching device wire cases remain required.

`scripts/tests/ipv6_owner_capture_test.py` reopens all four actual fixture groups and rejects 109 serialized packet/log corruptions, including coherent metadata edits, early/late retry packets, shortened quiet windows, lost permanent owners and invented NODAD probes. `--archive build/ipv6-owner-damaged.zip` preserves a separate ZIP for each group and reopens every archived control. `ipv6_owner_peer_test.py` verifies the live conflict barrier, explicit cleanup policy, fresh-PIO admission, equal monotonic ticks and rejected backward observations. `ipv6_owner_launch_test.py` executes eight invalid argument forms and requires rejection before privileged configuration. These checks supplement the complete wire and native matrices.

The ready-state subset contains 36 profiles for administrative, MTU and
carrier transitions. Both linkages, both firmware paths and all three adapters
remain required, with two workers and a separate sixty-second deadline per
profile. The ready-state subset includes nine native comparisons through
isolated static musl, dynamic musl and glibc clients. The same clients have been
checked on Linux 6.17 and 7.0. Controls travel over the healthy companion while
the subject is unavailable; native carrier changes use a veth port and a separate
administratively up promiscuous bridge observer. The readers match every serial
field to captured metadata, retain full four-second quiet windows and enforce
DAD completion observations between one and 2.1 seconds. They bind each adapter's prelude to its own
logical BEGIN captured on the companion. Firmware IPv6 traffic before that
boundary stays in the original capture; the same traffic after BEGIN is rejected.

The original kernel fails the administrative case by retaining `IFF_RUNNING`
while down. Its image and packets remain unchanged. The corrected kernel passes
all 36 clients. The first new reader rejected 18 completed UEFI executions because
it parsed firmware multicast as workload; those original producer receipts remain
failed. An audited reader correction independently accepts all 36 original packet
sets without rerunning their producers. Six images, 72 guest captures and 36 native
captures are independently checked; 594 changed evidence copies reject, including a 999.9-millisecond completion for every guest profile.
`scripts/tests/ipv6_device_capture_test.py` reopens actual Linux and UEFI fixtures,
checks native clock/loss rejection, and serializes twelve guest damage cases per
action, including a 999.9-millisecond completion and firmware moved after BEGIN.
`--archive build/ipv6-device-damaged.zip` retains and reopens an archive per action.
A later DAD readiness change exposed restored completions below the existing one-second minimum in eleven guest profiles. The failed images and captures remain rejected. Rounding the kernel deadline past its sampled ten-millisecond tick passes all 36 changed guests with the same client binaries and original bounds. Together with the 18 unchanged native comparisons, independent readers check six images and 108 captures and reject all 594 serialized and reopened negative copies. The actual client now emits each queried control record with one checked write; its formatter model also rejects short and interrupted writes. The sanitizer model requires tentative state at the old tick boundary and readiness one tick later. Full current-source hosted qualification remains required.

The device runner now selects all five states by default: ready, probing,
regenerating before a replacement probe, retrying after that probe, and exhausted
after four selected conflicts. `make test-ipv6-device` therefore requires 180
guest profiles; `sudo -n make test-ipv6-device-native` requires 45 comparisons on
the running Linux kernel. `--state ready` selects the original subset. Each
pending-state program is built once per linkage and reused with explicit state
arguments. Both workers, each sixty-second deadline and the complete observation
windows remain unchanged. CI runs the complete guest cohort in the existing
IPv6-expiry job and retains its actual inputs, images, serial logs and captures in
the `ipv6-device-wire` artifact. Native comparisons remain in the configuration
job and its `ipv6-configuration` artifact. Both jobs retain their seventy-five-minute
limits, and the complete workflow retains all 210 jobs and required aggregates.

The pending client queries actual owners before each selected conflict. Its
companion acknowledges only after the matching advertisement is recorded on the
subject adapter. Guest runs wait for the complete exact frame in the original
QEMU capture; draining a host TCP send queue alone cannot establish delivery
order across adapters. Carrier loss retains failed and current owners and permits DAD progress;
administrative down and invalid MTU remove the owners and restart DAD on recovery.
Readers require exact owner sets and connected-prefix counts without imposing
address dump order. Probing and retrying use the actual probe-to-ready interval
of one to 2.1 seconds. Regenerating during carrier loss has no replacement wire
probe, so its first ready observation must follow the actual conflict by two to
3.1 seconds in Axiom64. A native Linux 6.17.0-1022-azure or 7.0.0-1017-azure comparison may use a
3.212-second ceiling only with the actual kernel configuration and timer values
recorded before and after the C workload. CONFIG_HZ must be 1000; generation and
router-solicitation delays must remain one second, neighbor retransmission must
remain 1000 milliseconds, and DAD/nonce settings must retain their defaults.
Linux's timer wheel permits a 3.112-second schedule before the original
100-millisecond observer allowance. Missing, changed or unsupported native
proof retains the 3.1-second contract or fails validation. Guest comparisons
always retain 3.1 seconds. Original clocks, four-second observations and
sixty-second client limits remain unchanged. If the first post-loss inventory already sees readiness, the client
records it there before publishing that inventory. Host regressions check that
later polls cannot replace or duplicate the observation.

The retained diagnostic fixtures contain twelve static BIOS/modern Axiom64
executions and 24 glibc executions on the two pinned Linux kernels. Independent
inspection reopens twelve actual images and 72 captures. The committed reader
tests replay those original observations and reject 304 corrupted copies after
closing and reopening their archives. The shared decoder also matches all
54 original ready-state results and the exact rejection reasons for their 594
archived controls. These checks establish the diagnostic and reader subsets;
the complete corrected matrix is qualified separately below. Complete hosted
acceptance for the expanded source remains required.

The first expanded run completes all 180 guest clients and 90 native cases.
Eleven e1000 guest captures fail the required conflict-before-ACK order; their
original receipts, images and captures remain failed. A physical capture receipt
now gates each guest conflict ACK. The focused changed-controller execution
passes the original reader with the same client and kernel. A separate real
1.1-second delay of each first down-link ACK verifies that readiness is published
before the initial post-loss address inventory, rather than deferred to a poll.
`scripts/tests/qemu_capture_delivery_test.py` retains the original failed trace,
the corrected diagnostic and the delayed-ACK trace. It rejects incomplete records,
replaced or truncated files and excess frames without changing packet timestamps.
The corrected complete local matrix passes all 180 guest profiles and 45 native
profiles on each pinned Linux kernel. Independent readers reopen thirty guest
images and 540 original captures, match 432 physical delivery receipts to their
exact advertisements, and reject 5,862 serialized and freshly extracted corruptions.
The 4,494 guest controls retain every original ready-state rejection; the 1,368
native controls also reject excess reader latency, unstable clock offsets and
coherently changed conflict owners. The original sixty-second deadlines, both
workers, full observation windows, exact packet counts and zero-drop requirements
remain unchanged. Complete current-source hosted and feature acceptance remain
required; the earlier eleven failed ordering cases remain rejected.


`make test-ipv6-wire` also checks DAD state per address owner: retained permanent failures, stable retries after a generation-mode change, both link-local jitter endpoints, four distinct retained failures, finite configured-address removal and fresh recreation. Stable takeover tests preserve infinite, NODAD and six/ten-second finite lifetimes, exact flags, retry holds and last-owner prefix cleanup. Eight same-client Linux 7/static guest comparisons independently reopen eight images and 32 captures. NODAD replacements become usable without another probe; finite replacements retain their requested lifetimes. Earlier peers that acknowledged before injecting a conflict could shorten the observation. Those short reference windows remain excluded; corrected barriers retain the same client wait and require at least four captured seconds after the actual conflict. Full matrix coverage for these additional comparisons and complete hosted qualification remain required.

`python3 scripts/tests/ipv6_dad_inventory_test.py -v` drives the actual C observer through fourteen cases. Retiring and replacement dump records may overlap in either order before the old failed flag is visible; selection excludes the preceding identity, while final inventories still require exact counts. Duplicate fresh candidates fail. `python3 scripts/tests/ipv6_dad_capture_test.py -v` reopens actual guest/Linux captures and rejects 39 serialized packet, inventory, lifetime and timing mutations. Policy and launcher tests check the source-pinned native cleanup boundary and exact client argv/exit propagation. These checks and the full DAD matrices run in existing jobs; all earlier matrices remain required across the complete 180-job workflow. Full current-revision hosted qualification remains required.

Run `make test-ipv6-wire` for the [IPv6 packet-codec sanitizer checks](ipv6.md). They cover fixed and extension headers, unknown-option actions, fragment boundaries, address prefixes, pseudo-header checksums and production host output. `make test-ipv6-host` adds eight actual guest boots across both linkages, firmware types and virtio transports, using virtio-net and e1000 together. Each adapter must complete an explicit Ethernet readiness barrier, real DAD, duplicate conflict, five ND/echo phases, five malformed ND controls and twenty-four required damaged-capture cases, plus a firmware-bound control for each guest capture. Captured firmware traffic before that barrier remains separate from the eleven required kernel packets. The same client also checks tentative/failed prefix ownership, prefixless companions, explicit retained-route cleanup and three manual/connected metric-order cases with actual route inventories. The final phase uses a /128 address without a route back to the solicitor, requiring direct neighbor resolution. Valid peer requests, resolution replies and causal ordering are checked independently. Native comparisons run the same client through three linkages. Independent audits require all original packets, ordered Ethernet barriers, checksums and exact echo bytes. The same host client retains fifty-eight address/cache observations, six source queries and six raw samples for finite lifetimes. `make test-ipv6-lifetimes-contract` compares all three completed native and eight guest profiles with the source-bound complete Linux 7 reference. It validates all sixteen cache bytes, kernel birth/update timestamps, unchanged two/eight-second lifetimes and the original 0, 4.2 and 9.2-second samples. Separate bounded observations allow native periodic cleanup to finish before eight seconds for deprecation and by fifteen seconds for removal. The reader reopens and rejects 198 serialized damaged logs, including missing raw samples, renewed timestamps and invalid elapsed times. The retained earlier fixed-stage native failure remains separate. `make test-ipv6-wire` also checks the controlled peer's learned native unicast maintenance handling; capture audits require its matching advertisement without changing the original packet requirements. The production host checks also cover an expired source retained by a connected UDP description, fresh-source exclusion and copied output through final close and socket reuse. A focused before/after comparison uses actual Linux 6 and 7 observations and one static BIOS/modern guest on both adapters. All eighteen UDP rows match after the correction; four retained sends differed before it. Both actual images and eight original captures are reopened. Broader finite-address wire acceptance remains required. The first expanded eighteen-exchange host cohort passed eight guest profiles; only static musl passed its native packet-clock gate. Its glibc and dynamic-musl clock failures remain excluded. The corrected client waits for its exact local destination route before the /128 ND phase. Actual Linux 6 and 7 probes show that a NODAD address can leave tentative state before that route appears. A complete source-bound Linux 7 execution now passes all original phases and all four acknowledged permanent-source barriers. Its actual initramfs, client, log and captures are reopened. All eight current guest profiles pass with the corrected client and local-route inventory. All three current native clients return zero with unchanged inputs and zero packet drops, but their original realtime-to-monotonic clock bindings fail and remain excluded. Independent inspection validates packet content and all four barriers without accepting native timing. The local ABI comparison passes all eleven profiles and rejects 198 serialized changed logs. Full native packet-clock qualification and current-revision hosted acceptance remain required. Earlier failures remain retained. Full IPv6 socket and feature acceptance remain unfinished.

The host client also performs 114 real UDP connection/source observations across both adapters, with automatic routing and device binding. It covers manual-address scope, the default Linux labels, outgoing-interface priority, cross-interface fallback, deprecation and IPv4-compatible sources. A separate sanitizer regression covers equal candidates across three interfaces. The independent source reader requires every ordered outcome to match the executed Linux 7 reference and reopens 124 changed-log controls per comparison. The complete Linux 7 reference includes eight no-address unicast/site fallback observations while preserving all 106 earlier cases. Production-module regressions also exercise UDP/raw admitted output across both adapters, device bindings, empty/resolved neighbors, live/closed owners and small/fragmented payloads. They require no external loopback-source frame or leaked ownership, with a separate local UDP delivery control. Sixteen further module cases preserve synchronous oversize rejection and deferred `EMSGSIZE` when the interface MTU falls from 1500 to 1280 after admission. A separate targeted guest campaign passes all eight static/dynamic BIOS/UEFI transport profiles, with 64 fallback sends per execution. Real NS/NA exchange and ordinary UDP output establish the cached-neighbor controls before source withdrawal. Independent original captures show no external loopback source or destination; checksum-correct injected leaks are rejected. Local UDP delivery also passes. All eight full host profiles also pass with the deferred-MTU correction in 34.2ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“37.6 seconds, retaining every original phase and the 45-second deadline. The three native host clients returned zero with unchanged inputs and zero capture drops, but all original stable clock-offset checks failed; these captures remain excluded from timing qualification. Current native packet-clock qualification and full hosted acceptance remain required. `make test-ipv6-source-policy-contract` checks that controls modify the intended cohort when a log contains several test groups. The original address, lifetime, queued-output and packet scenarios retain their existing deadlines, including the 45-second host profile bound. Source-log comparisons do not qualify packet clocks.

Run `make test-ipv6-pmtu` for [learned IPv6 path limits and quoted raw/UDP errors](ipv6.md#learned-path-mtu-and-quoted-errors). Its shared C client runs 120 cases on both adapters across all six discovery policies, global/link-local destinations, thirteen ICMPv6 error combinations and ten malformed quotes per adapter. `sudo -n make test-ipv6-pmtu-native` uses three native Linux linkages. Original captures must bind each router hint to the actual emitted packet and verify subsequent data, fragmentation or rejection. Each hint and rejected send retains its full real fifty-millisecond observation. Hint observation begins at independent receipt of the complete injected frame, after any queueing delay. `make test-ipv6-pmtu-observation` replays captured delayed input and incomplete capture writes without changing packet timestamps. The independent reader also rejects altered packets, fragment fields, application results and observation intervals. `make test-ipv6-path-mtu` checks cache ownership and exact ten-minute deadline boundaries under sanitizers. These commands run in the existing network and host-policy jobs.

Run `make test-ipv6-expiry` and `sudo -n make test-ipv6-expiry-native` for actual 600-second path-cache expiry. The 32-path client covers both adapters, raw/UDP, global/link-local scope, equal/increasing/subminimum hints, a genuinely lower hint twenty seconds later, repeated queries and ordinary traffic. It checks 224 exact socket results and requires successful wire sends only after the original or independently learned deadline. Each execution also checks twenty cached-destination queries for both transports, shared aliases, invalidation and reconnect. Each original capture must reject twenty damaged controls, including a false refreshed raw getter, a foreign neighbor-probe source, a reply sent to a different assigned address, and four causal-clock corruptions. Probes retain assigned-interface ownership and replies must match the actual solicitation source. Native packet clocks remain bound to independent monotonic receipts with zero drops. Their original timestamps must preserve each owned conversation: barriers, neighbor request/reply pairs, quoted data, successful stages and heartbeats. Independent transactions may cross in receipt order without changing any packet clock or expiry interval. `sudo -n python3 scripts/ipv6_expiry_test.py` overlaps three isolated native profiles with eight guest profiles in four-VM waves, retaining the full roughly 622-second observation per profile. The dedicated `ipv6-expiry` job retains programs, loaders, actual images, input fingerprints, logs, original captures and negative fixtures. Current-revision hosted acceptance remains required.

The IPv6 guest driver accepts `--output-directory` for isolated run evidence and `--image-directory` for completed ISOs. Image staging and compiled inputs still use `build/`.

`make test-ipv6-send-model` checks rejection of altered native traffic-class controls, option-memory boundary results, source/program hashes and execution receipts. The complete output cohort preserves a separate `native-send-model.log`, `native-send-model.json` and probe products for each native linkage. `make test-ipv6-output-contract` requires these original bindings before comparing its 480 local send-control observations with all eight guest logs. The independent probe covers two received traffic classes and eight protected-control allocation cases. It does not replace packet checks: every original output capture, full rejection interval, stable native clock binding and zero-drop requirement remains mandatory. Offline historical comparisons must supply both `--historical-native-minus-one-class` and `--historical-native-optmem-max`; their result explicitly records that an independent original probe is absent.

The focused receive-control client is built as `build/ipv6-control-native`, `build/ipv6-control-static` and `build/ipv6-control-dynamic`. It emits 650 exact local observations for raw ICMPv6 and UDP. `scripts/ipv6_control_contract.py` compares three native logs with guest logs, checks all visible bytes and rejects eight damaged logs per guest profile. Cases cover control-buffer sizes, guard pages, payload ownership, peeking and shared options.

The `ipv6_control_faults` client adds 108 source-name observations across raw/UDP, `recvmsg`/`recvfrom`, twelve writable prefixes, peeking and protected output-length pointers. `scripts/ipv6_control_fault_contract.py` compares every visible address, control and payload byte, final result fields and queue ownership. It rejects ten damaged logs per guest. Output-length and address-copy fault ordering follows Linux 7.0. Older native kernels can differ on these side effects; use a matching Linux baseline for the complete comparison.

The `ipv6_control_header_faults` client adds 96 raw/UDP observations over twenty writable header prefixes and four NULL/zero-capacity name modes, with and without peeking. It invokes the actual Linux syscall with both pages readable and the second page read-only. `scripts/ipv6_control_header_contract.py` compares the complete original header, visible buffers, result fields and queue ownership, rejecting twelve damaged logs per guest. Original pointer bytes remain in logs; only unchanged input pointer slots are normalized during cross-process comparison.

Run `make test-ipv6-controls`, `sudo -n make test-ipv6-controls-native` and `sudo -n make test-ipv6-controls-contract` for the complete receive-metadata cohort. The linked client retains all three focused clients as standalone programs and executes their 854 cases before its 160 Ethernet receives: 1,014 observations per execution. The matrix covers three native linkages and eight normal guest linkage/firmware/transport profiles. Both adapters receive varying hop limits and traffic classes over global and link-local paths, with actual destinations, interface indices, aliases, queue-time option changes, truncation, peeking and copy faults. Each case checks a corrupted-checksum input and its valid original. Original capture audits reject 22 damaged controls per capture; the local readers reject another 240 damaged logs across eight guests. A complete campaign checks 22 original captures and 724 damaged controls with original packet clocks and lossless native receipts. Local ABI validation compares all eight Axiom64 profiles against three linkages on a Linux 7.0 reference VM. Reference-VM results do not establish native capture-clock acceptance. The existing CI network job runs the full cohort and uploads original packets, logs, images, programs and input manifests. Error-queue metadata interactions, outgoing ancillary controls and complete current-revision hosted acceptance remain required.

Run `make test-ipv6-errors` and `sudo -n make test-ipv6-errors-native` for [IPv6 extended error queues](ipv6.md#extended-error-queues). The shared client checks copied payload/control/address bytes, truncation and copy faults, output-admission ordering, shared-description lifetime and independent normal/error queues. Eight guest profiles and three native linkages retain both adapters and the original real observation intervals. Eight wide-vector groups check signed lengths, complete address spans and bounded totals before dequeue. Independent readers reject fourteen altered packet/log controls per capture. `make test-ipv6-fragment-observation` also checks delayed first-fragment release without shortening any wire timing gate. Clock-discontinuous native captures remain rejected. These targets use the existing network and host-policy jobs.

Each complete error-queue client additionally executes 472 local metadata and protected-copy observations before the existing error and wire cases. Received ICMPv6 errors return enabled packet-info, hop-limit and traffic-class controls before the extended error; local MTU errors omit received controls. Cases retain original headers, every visible buffer byte, alias options, post-queue option changes and dequeue behavior with peeking. `sudo -n make test-ipv6-errors-contract` compares three complete native logs with all eight guest logs and rejects fourteen damaged logs per guest, including incorrect length-store ordering, packet indices, written padding and changed pointers.

The same client then adds 160 Ethernet metadata cases after all 120 earlier wire cases, retaining both adapters, scopes and transports. Each received error quotes the actual emitted packet and supplies independently varied outer hop/class fields. Invalid-checksum errors have a different code; queued and ordinary pending errors expose incorrect acceptance. New independent capture checks reconstruct every visible byte and reject twenty-six metadata corruptions alongside the fourteen existing controls. Eight guest profiles pass all cases, with sixteen original captures and 640 rejected wire controls; the local log readers reject another 112. Three complete Linux 7 reference-VM linkages and their six original captures establish the reference ABI with independent interface inventories. Native CI still requires original kernel timestamps, independent monotonic receipts and zero drops for the complete captures. The existing network job uploads all evidence; reference-VM results do not establish that native clock qualification.

The same error client retains the plain phase and adds 160 outer-extension Ethernet cases, for 440 wire cases per execution. Both adapters receive independently copied Hop-by-Hop, Destination and repeated Routing headers on raw/UDP and global/link-local paths. The new reader adds 34 damaged controls per capture, while the plain and original phases retain 26 and 14. All 1,628 serialized wire controls reject across three native and eight guest profiles. The current native captures pass original-clock checks with zero drops, and both actual guest images are reopened against their exact kernel, client, loader and init products.

`sudo -n make test-ipv6-errors-contract` also compares 272 local receive-extension observations in all eleven full clients against a source-bound actual complete Linux 7 fixture. It rejects and replays 264 damaged logs, alongside the existing 472-row/112-negative error contract. Sixteen new length-output boundary observations reproduce twelve pre-fix differences and match after correction. Native fixtures verify their separate network namespace before setting SRH on owned interfaces and loopback. Original failed references with disabled SRH remain retained and excluded. Hosted acceptance and broader IPv6 requirements remain separate gates.

The native error fixture reserves UDP destination port 59999 from automatic source-port allocation inside each private network namespace. Otherwise a client can select that same source port, receive its own datagram and produce no ICMP error. Existing reservations remain intact, and explicit binds to the destination still work for the normal-data lifetime case. Each preexecution record retains the original and applied reservation and ephemeral range. `sudo -n make test-ipv6-error-destination` checks actual allocation and error delivery with only two ephemeral ports, existing reservations and parent-namespace rejection. The complete native error target includes these checks. Client cases, all three linkages, ICMP rate settings, readiness deadlines and guest coverage retain their existing behavior.

`make test-ipv6-copy-model` checks the independent native source-address probe, both supported store orders, wrong-model rejection and altered evidence. Native ordinary/error cohorts run that probe before collecting their Ethernet workloads and retain its raw output, actual source/product copies and kernel binding. The local and wire readers validate every native model-specific field before comparing common results and the unchanged Linux 7 guest expectations. Protected address/length effects stay explicit; they are not omitted from comparison. Historical captures without this probe require an explicitly supplied, documented native copy order for offline auditing. Existing clock and zero-drop requirements remain mandatory.

Run `make test-ipv4` for the [initial IPv4 and raw ICMP matrix](ipv4.md#verification). It uses both adapters together, controlled Ethernet peers, QMP link changes, and GDB cache/backpressure/device-fault probes. Results accumulate in `build/ipv4-results.json`; CI retains the logs and debugger commands. The administrative-down observer now requires both UP and RUNNING to clear, then logs the queried flags. All eight local cases pass with the original workers, packet checks and complete ten-minute lifetime. Independent checks open both images and sixteen captures and reject 564 reopened evidence changes. Original hosted failures remain unaccepted.

Run `make test-ipv4-gateways` for the complete static/dynamic, BIOS/UEFI and modern/legacy gateway cohort, and `sudo -n make test-ipv4-gateways-native` for all three native comparisons. Each NIC sends twelve original raw/UDP datagrams with exact source aliases and independently resolved next-hop MACs. The peer acknowledges a phase only after observing its datagram; original captures and client queries must agree in execution order. The same process or boot adds fourteen raw/UDP datagrams per NIC across zero, other-interface, explicit, own and removed-source configurations. It also sends 110 retained-source datagrams through six address phases and eight output methods, including named calls to the connected peer, writes, vectors and duplicate descriptions. A separate zero-source description sends before any query. Unnamed native sends preserve the original zero source through a current cache or select the current preferred source after a cache miss; method order alone cannot distinguish them. Native comparisons require both outcomes and keep raw/named sources, socket names, checksums and query-model markers exact. Guest cache expectations remain tied to the release model. Removed selected-source errors and cache recovery are checked separately. Ethernet barriers require the actual datagram without relying on an IP control address. Each adapter retains twenty-two rejected gateway controls and 31 unconfigured-output packet/log controls. Native checks also exercise two valid cache variations through both the live peer and independent checker. The production output sanitizer test also injects invalid and expired ARP replies into the kernel module; damaged saved captures remain separate auditor checks. Guest inputs bind the compiled client and its local headers to their source hashes. The image audit opens each ISO and checks its kernel, init, client, BusyBox, dynamic loader when needed, and exact boot script. CI retains those input records and all damaged archives. These focused routing checks retain the separate full fragment and ten-minute PMTU gates.

Run `make test-ipv4-path-mtu test-ipv4-paths` for the shared cache policy and production retained-destination, route and link ownership checks, and `sudo -n make test-ipv4-fragments-native` for all three native fragment, expiry and path-MTU clients. The IPv4 guest matrix includes eighteen PMTU cases per adapter, each with unrelated route edits, temporary on-link/gateway query overrides and recovery before the original policy datagrams. The final case changes the actual link MTU and checks retained descriptions and shared exception adjustments without renewing their deadlines. Sixteen damaged PMTU fixtures per adapter must fail, including missing or false held-description, route and link query records. Original PCAPs and compressed PMTU negative fixtures remain under `build/ipv4-*`; focused native PMTU runs are explicitly separate from full expiry acceptance.

Native IPv4 fragment comparisons also retain read-only Linux reassembly, ICMP, socket, route, neighbor and memory counters in `native-kernel-state.jsonl`. Snapshots bracket setup and shutdown, each expiry event, and the original 59/66/100-second checkpoints. Each snapshot retains raw counter files, actual clock brackets and explicit read failures; the receipt binds its complete file hash. Counters are sequential observations and do not replace packet evidence. Capture-shutdown errors retain their interface index alongside the original client failure; missing capture statistics remain unqualified. Acknowledgement failures report the interface, control phase, actual poll result and events; timeouts report `ETIMEDOUT` instead of an unrelated earlier syscall error. The original fragment lifetime, duplicate and suppression spacing, quiet windows, profile deadlines, packet-clock checks and zero-drop gates remain mandatory. A missing expiry quote still fails.

The full native fragment peer completes one actual closed-port UDP error before
releasing its first original fragment controls. The independent reader requires
the exact request and complete returned quote, unchanged default rate settings,
original packet clocks and byte-identical control release after that quote.
Twelve serialized altered receipts must fail when reopened. This setup leaves
the original simultaneous adapter workload, sixty-second reassembly expiry,
suppression observations and ten-minute PMTU lifetime intact.
`sudo -n make test-native-icmp-budget` separately retains 256 fresh namespaces
each for cold simultaneous, staggered and primed simultaneous error pairs.
Cold global-rate suppression is recorded explicitly; staggered and primed pairs
must return both original quotes. The staggered second writer waits for the
first complete input syscall, then observes the original one-millisecond gap.
A missed shared deadline cannot turn this control into a simultaneous pair.
The reader checks both actual syscall brackets and reopens twelve damaged
controls, including collapsed and reversed staggering. The same target also
runs three production-writer regressions with real pipes and monotonic clocks.
They delay the first writer by zero, three and twenty milliseconds after the
start barrier and require both complete payloads plus the original minimum
gap. These scheduling regressions do not establish ICMP or guest behavior.
CI retains these native controls in `native-icmp-budget`, alongside the complete
fragment evidence. These comparisons do not establish guest behavior.
Qualification with the three original client products reopens six captures and
all 298 damaged controls, including the original expiry, PMTU and lifetime
corruptions. Each profile retains both required expiry quotes with zero global
suppression. All 768 fresh-namespace controls pass their explicit contracts;
132 cold simultaneous profiles record suppression, while staggered and primed
pairs return every quote. Complete current-revision hosted CI remains required.

The full native and normal guest clients also retain the actual ten-minute path limit. Both NICs age together, with repeated socket queries and failed DO sends before two complete post-expiry datagrams. Original PCAP timing and native monotonic receipts must prove the unchanged interval. The outer normal-boot limit is 780 seconds to include this additional observation; fault profiles retain their 120-second bound. `--lifetime-only` isolates the complete native PMTU lifetime without claiming the other fragment and policy cases.

`python3 scripts/tests/ipv4_fragment_observation_test.py -v` replays delayed native capture observations through the expiry scheduler. It also exercises the production collector and injection path, checking exact frame matching, missing/short injections, unchanged duplicate timing, the final quiet interval and guest spacing. Native context spacing begins after independent capture receipt; its eight-second requirement and all expiry audit thresholds stay intact.

The IPv4 matrix prepares one normal and one fault image, then runs two profiles concurrently per phase by default. Each worker has its own process session, QMP socket, logs, captures, UEFI variables and inherited debugger listener. The kernel and prepared image stay immutable until the phase finishes. Worker exit status, exact profile identity, result presence and shared product hashes gate the combined result. `scripts/tests/ipv4_matrix_test.py` uses real subprocesses to check overlap, false-success and missing-result rejection, changed-image rejection and descendant cleanup. Worker timestamps and image hashes remain in `build/ipv4-*-worker-results.json`. The number of guest profiles and CI jobs is unchanged.

Run `make test-udp` for the [IPv4 UDP matrix](udp.md#verification). It first runs `scripts/tests/udp_peer_test.py` to check that the peer follows the learned path's DF policy while preserving checks for other destinations, checksums, fragment flags and exact payloads. Independent Ethernet peers inspect checksums, ports, lengths, and exact bytes; the guest exercises client/server and socket lifetime behavior. Results accumulate in `build/udp-results.json`; CI retains logs and fault-injection commands. All eight changed observer cases pass with their original bounds, including the five-second delayed UEFI fault injection. Independent flag, recovery and fault-isolation checks open two images and sixteen captures and reject 76 reopened corruptions. `scripts/tests/administrative_flags_test.py` exercises the actual IPv4 and UDP helpers in eight synthetic cases; it accepts cleared operational flags and rejects administrative-up or RUNNING observations. TCP, DNS TCP fallback, downloads, and the complete networking release remain required.

Run `sudo -n make test-dns-native` and `make test-dns` for [actual musl IPv4 UDP lookups](dns.md#verification). Both linkages check 17 cases, eight concurrent queries and 128 reclamation cycles. Four BIOS/UEFI and modern/legacy guest kernels use both Ethernet drivers together. Independent peers validate query order, answers, filtering, retries and checksums; every frame must match an actual guest packet receipt without capture drops. ETH_P_ALL observers retain outgoing queries, incoming replies and separately accounted non-IPv4 frames, then retire reception and drain before statistics. Run `sudo -n python3 scripts/tests/dns_packet_observer_test.py` for the actual C observer and `python3 scripts/tests/dns_capture_test.py --matrix-results build/dns-results.json` for archived physical/record corruption checks across the current matrix. Evidence uses `build/dns-*`. The AF_INET-only boot fixture disables IPv6 before starting either client. Every execution retains its source, programs, loader, kernel, initramfs, actual ISO, original captures and any rejected incoming frame in a new `build/dns-fixture/run-*` directory. The thirty-second guest deadlines and all strict peer checks remain required. Native resolver/hosts mounts and listeners are confined to verified private namespaces. The complete DNS/network release requirements remain open.

Run `make test-normal-manager` for [normal DHCP-to-application DNS](dns.md#normal-dhcp-to-query-path). All 32 normal-init cells retain their original process, desktop/input, saved-state and filesystem checks. The console logs in as an ordinary administrator and authenticates sudo for protected state and manager signals. The same serial shell, graphical processes and terminal window must survive the manager restart. Both musl linkages query using current ACK nameservers before/after PID1 restart; peers retain exact wire bytes, query order, checksums and adapter routes. No-NIC/no-server controls skip application queries because no lease is accepted. Packet evidence uses `build/normal-init-login-*/normal-init-*-dns-packets.json`.

Authenticated boot and service fixtures retain their inputs, added identity client, images, serial captures and results in separate `build/interactive-login-*` and `build/normal-init-login-*` directories. Successful disk checkpoints use `.raw.gz`; decompressing them reproduces the independently checked disk bytes and recorded SHA-256. `python3 scripts/tests/fixture_archive_test.py` verifies retained bytes and refuses foreign paths, symlinks and shared inodes before cleanup. Failed disk checks retain their original image.

Run `make test-netlink-codec` and `make test-netlink` for the [route-control checks](netlink.md#verification). Build `build/netlink-native` and run `sudo python3 scripts/netlink_native.py` for the common Linux comparison in an isolated network namespace. Guest evidence lives in `build/netlink-wire/`: the actual boot image, source and executable hashes, logs, per-adapter packet captures, and firmware/adapter observations. The guest fixture disables IPv6 before its IPv4-only client starts, so automatic IPv6 address probes cannot enter the strict ARP/IPv4 peer. `python3 scripts/tests/netlink_peer_test.py` replays a captured DAD frame and requires the peer to reject it. Native logs and results use `build/netlink-*` and record the running kernel version.

Run `make test-address-codec` and `make test-configuration` for the [complete address and ownership/recovery checks](network-configuration.md#verification). Build `build/configuration-native` and run `sudo python3 scripts/configuration_native.py` for common Linux address messages in a private network namespace. Native checks exclude Axiom64-specific journal recovery and quotas. Guest/native evidence uses `build/configuration-*`.

Run `make test-dhcp-codec` for host codec/state/profile sanitizers, `make test-dhcp-modules` for their 12 guest cases, and `make test-dhcp-transport` for four real-wire cases. Evidence uses `build/dhcp-*`; the [configuration documentation](network-configuration.md) describes exact counts and remaining normal-service/reboot/fault coverage. These module fixtures do not run the normal startup daemon.

Run `sudo python3 scripts/address_query_test.py` for three native libc comparisons of actual IPv4 withdrawal between address and mask reads. The manager matrix adds eight regression boots, covering both musl linkages, firmware types and virtio transports on both Ethernet adapters. The original 104 manager cases remain required. The wrapper performs real address removal; injected I/O errors separately check preservation of caller outputs. Native reports and logs use `build/address-query-*`; guest logs use `build/manager-address-query-*`, with separate `build/axiom64-manager-address-query-*.iso` images.

Run `make test-static-address` and `make test-manager` for the [manager composition checks](network-manager.md). Use `python3 scripts/manager_test.py --firmware bios --transport modern` for one CI cell. Reports retain each peer's counters even when verification fails; actual child status and independent address/route/file observations must agree with wire checks. `python3 scripts/manager_peer_test.py` replays complete client packets across successive leases, checks release against the latest ACK server, and rejects the prior server. `python3 scripts/manager_reboot_test.py` runs eight fresh ext2-root boot pairs, checks saved profile/hint metadata independently on the host, and requires new INIT-REBOOT transactions and ACK-derived configuration on both Ethernet adapters. The completed client/service protocol, carrier/device and normal-init acceptance is mapped in [the acceptance record](network-manager-acceptance.md).

Run `make test-random-native` and `make test-random` for [kernel randomness](random.md). Native ASAN/UBSAN covers cryptographic vectors and pool/generator/source transitions. Twenty actual guest kernels check both musl linkages, BIOS/UEFI, trusted RDSEED, CPU entropy absent, RDRAND alone, disabled CPU trust, initialized output, explicit early output, nonblocking errors, initialization waits/signals/restarts, musl retry, device polling, and user-copy failures. Initialized cells repeat as independent kernels and reject repeated samples. Logs/results use `build/random-*`; [randomness](random.md) describes the additional seed-lifecycle and real TLS/key-generation checks.

After building the OpenSSL providers, run `python3 scripts/tests/openssl_inputs_test.py -v` to check the completed runtime build manifest and reject altered executable bytes, library links, Linux-header recipes and cache directory identities. Cryptographic tests verify the complete recorded fingerprint, current libc and header recipe, and every staged product before running the clients.

Run `make test-credentials-policy`, `sudo -n make test-credentials-native` and `make test-credentials` for the [credential and permission contract](credentials.md#verification). Host sanitizers check allocation/lifetime and policy. Three native Linux clients and eight guest kernels require all identity, capability, file/mount/path, signal/network and IPC phases. Ext2 fixtures require fresh-remount owner decoding, independent host fsck and full-width inode inspection. Logs/results use `build/credentials-*`; account databases, authenticated sessions and the wider F09 requirements remain open.

Run `make test-account-normal` for actual installed init/Bash login: two RAM boots plus four ext2 create/reboot pairs cover BIOS/UEFI and both block transports. These retain private first-boot creation, failed login, complete ordinary identity/lookup/protection checks, authenticated sudo, logout, killed-console recovery, a real one-second restart and authenticated shutdown. Host dumps and filesystem checks verify the persisted account generation, private home/file and login records. `--directory` selects a fresh output directory; `--storage` and `--firmware` allow focused diagnosis without changing the default matrix.

Run `sudo -n python3 scripts/account_management_ext2.py --journal --campaign clean --directory build/account-management-journal-clean` for persistent administration on owned journaled ext2 fixtures. The default sixteen variants cover both libc providers, static/dynamic linkage, BIOS/UEFI and modern/legacy block transports. Each runs prepare, exercise, concurrent-update and fresh-kernel verification phases, retaining the actual guest disk after each phase. Twelve real commands contend inside each concurrency phase; variants run serially to avoid host I/O contention. Each guest retains the 120-second deadline. Native `debugfs` exports and strict `e2fsck` checks verify the account generation, full-width ownership, private modes and retained home data. `--campaign storage` selects read-only and full-volume failures; `--campaign fault` selects observed device errors and VM power cuts. A positive `--fault-limit` is a preliminary subset and cannot establish complete fault acceptance. Journaled fixtures use normal guest recovery; the unjournaled controls retain explicit checked recovery. Expected journaled selections come from Linux journal-only replay on a separate observation copy. The actual interrupted guest input stays unchanged and must recover inside Axiom64 before strict postchecks pass. The [native replay option](https://man7.org/linux/man-pages/man8/e2fsck.8.html) performs no further checks or repairs on that observation copy.

Run `python3 scripts/rename_test.py --directory build/account-rename-guest` and `python3 scripts/account_home_test.py --directory build/account-home-guest` for atomic destination exclusion and descriptor-owned home cleanup on RAM and ext2. Both retain 32 guest cells, unchanged 90-second deadlines, actual binaries, source snapshots, serial logs and checked persistent images. Native comparisons add `--native --fixtures /tmp/FRESH-NAME` and require root; home controls also support `--native --sanitize` for GNU ASAN/UBSAN. Choose new output and fixture directories for each invocation. Home controls exercise twenty-four behavior groups, including visible mutation followed by a reported error, publication collisions, foreign replacements, nonempty directories, ambiguous creation, descriptor release, actual creator termination and protected creation proofs. These modeled errors do not establish complete real-storage or VM-crash recovery.

Run `python3 scripts/account_home_reboot_test.py --directory build/account-home-reboot` for sixteen ext2 create/reboot pairs across both musl providers, static/dynamic linkage, BIOS/UEFI and modern/legacy block transports. Each pair requires a different actual kernel boot UUID, recovers an attested empty pending home and prepared stage, keeps published data, and preserves nonempty, unproven and replacement entries. Ordinary owners remain unable to access the trusted proof. Host `debugfs` independently compares saved keys with the persisted attributes and verifies full inode/owner/mode identities and data; all 32 phases require strict `e2fsck` checks and retained compressed/raw-image hashes. The deadline remains 90 seconds per boot. This verifies the home recovery primitive across clean reboot; account-generation intent coordination and VM power-loss acceptance remain required.

The process-identity comparison waits for the joined thread's procfs entry to disappear before requiring `ESRCH` from unread and rewound descriptions. Linux can wake `pthread_join` before kernel task retirement. The wait uses that observable namespace condition with a two-second bound; all original observations and the 90-second profile deadline remain. See the [Linux exit ordering](https://github.com/torvalds/linux/blob/v6.17/kernel/exit.c) and [join wakeup during memory release](https://github.com/torvalds/linux/blob/v6.17/kernel/fork.c).

The [resource quota comparison](resource-limits.md) observes the same retirement condition before requiring a joined thread's quota to admit a new fork. Run `sudo -n python3 scripts/tests/resource_thread_retirement_test.py` on a Linux host with two available CPUs for 10,000 actual quota cases with separate joiner and worker CPUs. It retains the compiled comparison, source hashes, complete output and owned-namespace process result. CI runs this regression before the six native resource profiles; the original quotas, rejection assertions and deadlines remain required.

Run `python3 scripts/account_transaction_test.py --directory build/account-transaction-guest` for the combined generation/home protocol on 32 RAM/ext2 guest cells. Native comparisons add `--native --fixtures /tmp/FRESH-NAME`; GNU ASAN/UBSAN adds `--native --sanitize`. Eighteen groups kill the actual owned writer at intent, home, generation and pointer boundaries; test reported errors after visible rename and partial writes; preserve unproven/foreign/nonempty state; reject malformed or truncated authority; require a preceding complete generation to remain readable with writes blocked during a validated unresolved rollback; and deny ordinary access to the private intent. Run `python3 scripts/account_transaction_reboot_test.py --directory build/account-transaction-reboot` for sixteen independent ext2 create/reboot pairs with the same actual transaction writer. Each pair verifies a different kernel UUID and independently decodes the persisted intent, attributes, current pointer and all three account files. Both harnesses retain unchanged 90-second boot deadlines, exact source/product logs and strict host filesystem/compressed-image receipts. Clean reboot and modeled write errors do not establish complete VM power-loss or real-device fault acceptance.

`scripts/tests/console_prompt_test.py` and `normal_login_test.py` replay retained interrupted Bash prompts at every byte boundary. The normal console readers recognize complete prompts across known kernel diagnostics, DHCP `NETWORK_MANAGER_BOUND` records and PID1 manager spawn/reap/exit records while keeping raw serial evidence and its offsets. The retained supervision fixture contains the actual interrupted prompt after a manager was killed. The queued revalidation command is sent once after the complete prompt; malformed or partial manager records cannot join it. They continue waiting for an incomplete prompt, child progress or unknown inserted text. The graphical recovery tests retain their actual keyboard sessions, framebuffer captures and 180-second deadline.

The corresponding-source archive includes C/header helpers under `scripts/`, all data under `scripts/tests/fixtures/`, and the Python/shell scripts. `scripts/tests/source_bundle_inputs_test.py` builds the native ICMP control from extracted source, checks captured serial bytes, retained journal inputs and target observations, then runs the real prompt, rotation-export and native journal-oracle regressions from extracted archives with checkout fallback disabled. Rotation export recognition omits only complete known kernel diagnostic records from its observation view; captured logs stay unchanged, and every decoded file must still equal the native disk export. The complete GNU verification kit retains its separate execution and relinking checks.

Run `make test-vm-state` for the normal persistent launch helper. It checks exclusive ownership, preservation after actual guest changes, incomplete/invalid metadata and symlink rejection, then boots the full packaged userspace twice with administrator creation and later required login. It checks guest data and host filesystems after both boots. Account and existing normal desktop/service gates are required in CI; local results alone do not establish full account acceptance.

Run `sudo -n python3 scripts/account_logbook_rotation_test.py --native --directory build/account-rotation-native --fixtures /tmp/axiom64-account-rotation` for native crash/error/short-write publication controls and expiry. Run `sudo -n python3 scripts/account_logbook_rotation_guest.py --directory build/account-rotation-guest` for 48 unwrapped RAM/ext2 boot phases and one actual default-limit guest overflow. The guest observer checks full-width identities, active leases carried through multiple generations, mixed denied/sudo events, exact retained history, protected metadata and fresh-boot recovery. Host decoding independently rebuilds frame checksums, state and all four projections; ext2 exports must equal actual guest-read bytes. Clean reboot proves persistence across a new kernel, while VM power loss and block-failure recovery remain separate acceptance work.

Projection publication batches payloads in 4096-byte writes before the existing synchronization and rename steps. `python3 scripts/tests/account_projection_write_test.py --directory build/account-projection-write` checks exact utmp, wtmp, btmp and audit bytes across native Linux and both target libc providers, with static and dynamic linkage. It also exercises real interrupted, short, zero-progress and failed writes. The native dynamic comparison supports `--sanitize` with AddressSanitizer and UndefinedBehaviorSanitizer. These callback checks complement the guest rotation and recovery cases.

`sudo -n python3 scripts/account_logbook_default_ext2.py --directory build/account-rotation-default-ext2` uses the production 32 MiB journal limit and configured 1024-live-session limit on owned 256 MiB journaled ext2 fixtures. Each of sixteen provider, linkage, firmware and transport cells rotates the full journal, shuts down and reopens the actual volume in a fresh kernel. Both boots retain a 600-second deadline and 512 MiB VM memory. Independent native checks verify all archived frame bytes, projections, protected metadata, strict filesystem checks and unchanged history after reboot. The four firmware/transport CI lanes divide these cells in addition to their existing smaller cases and RAM boundary test.

Run `sudo -n python3 scripts/account_logbook_rotation_ext2.py --journal --directory build/account-rotation-storage` to observe actual device writes and flushes, inject errors and power cuts, then boot normal guest recovery. Each guest keeps its 90-second deadline. `--shard-count N --shard-index I` partitions the observed phase/write/flush targets while retaining the complete baseline observations in each shard. Indices start at zero. Every selected target still runs the requested cache and fault modes. `target-selection.json` records both the complete and selected targets. A shard is a partial result; complete acceptance requires every index and all provider, linkage, firmware, transport, scenario, cache and fault combinations. The default shard count of one retains the complete original target order. `scripts/tests/account_storage_shards_test.py` checks exact coverage and rejects missing, duplicate or altered selections; these partition checks do not establish guest recovery.

For interrupted journaled inputs, the verifier retains the raw read-only filesystem check and observes journal-only replay on a separate Linux copy. Existing bounded recovery validators check any remaining allocation findings. Failed checks stay recorded as failed. The actual guest receives the original disk bytes and must recover them before strict post-recovery checks pass. `python3 scripts/tests/account_rotation_journal_oracle_test.py -v` replays retained failures, rejects unrelated directory damage and checks that observation never changes guest input.

The QMP client retains startup notifications received before the greeting and waits within its existing negotiation deadline. `python3 scripts/tests/qmp_greeting_test.py -v` replays a captured early RESUME through real Unix sockets, checks fragmented messages and capability negotiation, and rejects unexpected replies, missing greetings and event streams that exceed the deadline. Source-export checks run the same controls from the extracted archive. Guest recovery remains covered by the VM matrices.

After each rotation shard, `python3 scripts/account_rotation_storage_coverage.py collect --directory RESULT --output RESULT/coverage-index.json` binds its recorded executions, native postcheck logs, actual request prefixes and compressed/decompressed guest disks. Collection expects one provider, linkage, firmware, transport, scenario and cache selection with all three fault modes. `verify --indices PARENT --output REPORT.json` requires all 64 combinations and every shard index. The runner's native account-record and filesystem checks remain required; coverage validation cannot substitute for them. `scripts/tests/account_rotation_coverage_test.py` checks the complete cross product and rejects omitted variants, targets, fault modes, changed deadlines and mixed source/product inputs.

Administration coverage uses `python3 scripts/account_management_storage_coverage.py collect-clean --clean-directory CLEAN --storage-directory STORAGE --output REPORT/coverage-index.json` for each complete administration/storage-control pair, and `collect-fault --directory RESULT --output REPORT/coverage-index.json` for each complete cache-model fault run. Its `verify --indices PARENT --output REPORT.json` command requires all sixteen control variants and all 32 fault variants. Physically identical phase boundaries share one fault target, while every observed phase label must remain covered. Raw interrupted-volume checker failures remain failed observations. For dirty journaled inputs, the existing bounded retirement checks inspect the separate Linux-replayed view; every actual recovered guest disk must still pass strict filesystem checks. Non-crash and unjournaled checks keep their existing policy.

The workflow defines sixteen administration/storage-control jobs, 32 all-target administration fault jobs and 32 paired-scenario rotation jobs. Each rotation job restores its inputs and tools once, then runs basic and expiry profiles with separate producer invocations, baselines, evidence directories and coverage indices. Expiry still runs after a basic failure; either failure rejects the job. The 64 provider/linkage/firmware/transport/scenario/cache profiles retain their complete observed target lists and all 3,840 error and power-loss cases. Each published rotation artifact retains both scenario directories, and the coverage aggregate requires all 64 indices. Every job restores the same run's source/build inputs and keeps the original guest deadlines. Coverage jobs require complete indices across both libc providers, linkages, firmware paths, transports, scenarios, cache models, fault modes and shard indices. The final aggregate requires these jobs and every earlier suite to succeed. Matrix and validator unit tests check scheduling and rejection behavior; actual guest executions and their retained evidence establish recovery. An ownership test verifies that the ordinary runner can publish completed traces created by root without changing their bytes or private modes. Ownership transfers happen after producers and collectors exit.

Run `python3 scripts/tests/gnu_utmp_reader_test.py --directory build/gnu-reader-controls` to validate the pinned GNU reader against independently encoded records, malformed input, changed dependency/notice rejection and a byte-identical relink after moving the kit. The corresponding-source artifact includes the object, every actual linker input, relink recipe, complete upstream inputs and notices.

Run `make test-resolver-native` for native Linux file/ownership contracts with sanitizers and `make test-resolver` for four guest cases. Logs/results use `build/resolver-*`, including the native kernel version. The [resolver metadata contract](network-configuration.md#owned-resolver-metadata) describes output bounds, permissions, manual ownership, and the controlled publication failures. These tests publish metadata in isolated directories; actual application lookups are covered separately by [the UDP and normal DHCP-to-query gates](dns.md).

Run `make test-clock-codec` and `make test-clock` for [counter clocks and elapsed-wait checks](time.md#verification). Native sanitizers check scaling and bounded ACPI parsing; 24 guest cases independently time storage flushes across firmware, transports, normal HPET, absent/unsupported HPET fallback, and zero/three-second delay. Delayed cases require absolute futex and interval-timer expiry. Results and traces use `build/clock-*`; the ordinary full OS/thread/storage suites remain required.

Run `make test-file-locks` for the [advisory lock contract](file-locks.md#verification-and-limits). The harness compares three native Linux programs and sixteen guest suites across BIOS/UEFI, modern/legacy virtio, RAM/ext2 and static/dynamic musl. Traces must agree, retained descriptor/signal/teardown cases must pass, and the real ext2 seed file and host fsck are checked. `make test-file-locks-native` runs only the native comparisons. Logs/results use `build/file-lock-*`.

Run `sudo -n python3 scripts/http_download_test.py --native --output build/http-downloads` for all six native curl provider/linkage comparisons. `scripts/http_download_failure_native_test.py` adds actual DNS failure, refused connections, unreachable-neighbor deadlines and denied output in an owned Linux network namespace. `scripts/http_download_wget_native_test.py` compares the OpenSSL helper, default-store failures, its numeric-IP limitation and the internal fallback described in [ports](ports.md). Host resolver, account and trust files remain checked against their original bytes.

Run `python3 scripts/http_download_test.py --output build/http-downloads` for the complete curl guest matrix. Then run `python3 scripts/http_download_verify.py build/http-downloads --source-root . --report build/http-downloads/actual-evidence.json --negative-controls build/http-download-controls`. The independent reader reopens actual retained source, selected products, kernel/initramfs components inside each ISO, complete raw logs and both adapters' packet captures. It reconstructs full HTTP response bytes and TLS negotiation/encrypted records, and rejects eleven changed or missing actual-evidence controls. It does not decrypt TLS traffic.

Run `sudo -n python3 scripts/http_download_normal_test.py --output build/http-download-normal` for ordinary authenticated sessions. Every selected provider/linkage/firmware/transport cell boots RAM, creates a writable ext2 system and reboots that disk in a fresh kernel. Each kernel retains its 180-second deadline and both Ethernet adapters. Both linkages and providers remain in the default full matrix; narrower selectors are development subsets. Sessions use production DHCP and resolver updates, the installed curl where selected, private ordinary-user files and authenticated administrator trust changes. Reboot checks verify persisted files and trust before new downloads. The complete run retains actual disks, source-built clients, raw logs, captures, exported file bytes and two strict filesystem checks per disk.

Run `sudo -n python3 scripts/http_download_normal_verify.py build/http-download-normal --source-root . --output build/http-download-normal-audit --negative-controls build/http-download-normal-audit/controls`. This reader independently checks selected producer identities, actual archive and ISO products/configuration, firmware, raw command exits, boot identities, DHCP ACKs, DNS query/reply bytes, full HTTP data, TLS records and native application inventories. It reopens the final disk with native filesystem tools and compares both phases' actual exports. Damage controls retain changed copies and their rejections. Completed root-created evidence transfers to the ordinary uploader only after producers and readers exit; private modes and bytes remain unchanged.

Run `sudo make test-ownership-native` and `make test-ownership` for [network manager singleton ownership](network-manager.md). Six native cases and eight guest boots exercise real process contention, fork/exec, process death, private path metadata, permanent inode lifetime, and inode substitution. Guest ext2 cases require checked unmount, host fsck, and preserved seed bytes. Logs/results use `build/ownership-*`; normal concurrent manager startup is verified by the separate [client/service acceptance](network-manager-acceptance.md).

Run `make test-account-desktop` for [authenticated graphical sessions](accounts.md#authenticated-desktop). Each normal boot drives five real logins, tests absent/wrong/stale cookies and cross-user device/process access, reads the mapped terminal's pixels, injects keyboard commands into the ordinary shell and verifies its identity. Console SIGKILL, Xorg SIGKILL, graphical-shell exit and serial logout must retire the recorded processes, clear all framebuffer pixels before the next login prompt and require a new cookie. The default matrix includes both firmware paths and RAM/ext2 create/reboot cells. `--storage ram --firmware bios` selects a focused run. Host QMP captures, source/product hashes, serial logs and filesystem checks remain in the selected output directory.

`sudo -n python3 scripts/tests/desktop_authority_test.py --isolated` checks bounded Xauthority parsing and actual Xvfb/Xlib cookie acceptance and denials. `sudo -n python3 scripts/tests/desktop_terminal_test.py` checks actual owned, foreign, root and background Linux PTYs. The [parent-death and synchronous signal-wait matrices](threads.md#parent-death-and-synchronous-signal-waits) retain native comparisons and both guest linkage/firmware profiles. These focused checks accompany the full workflow; complete account acceptance and existing desktop/service integration remain required.

The IPv6 output cohort also checks 192 Ethernet ancillary sends per execution after its 432 earlier wire cases and 480 local observations. Run `make test-ipv6-output` and `sudo -n make test-ipv6-output-native` for the eight guest and three native profiles. Distinct unresolved neighbors hold four large datagrams per adapter until a separate packet exchange proves input overwrite, shared-option changes, socket closure and descriptor reuse. Independent readers require actual neighbor release before queued fragments, unchanged original payload/header bytes, full rejection observations and causal packet clocks. They reject fourteen earlier and twenty-eight ancillary damage controls per capture. Musl's protected-control case enters the kernel through the direct syscall; ordinary valid sends retain the libc wrapper. The existing workflow jobs and all earlier variants remain required.

`make test-tcp6-replies` and `sudo -n make test-tcp6-replies-native` compare
twenty [TCP reply cases](ipv6.md) per adapter across global and identical
link-local tuples. Both musl linkages, BIOS/UEFI and modern/legacy virtio retain
e1000 on the companion interface. Three local Linux 6.6 native profiles and eight
guests pass with twenty-two original captures. Readers require exact reset
addresses, ports, sequence/acknowledgment values, flags and checksums, and complete
fifty-millisecond reply/silence observations. They freshly reopen sixteen altered
captures/logs per interface, actual boot images, compiler products and incomplete
matrices. A same-client, identical-root-image comparison against the preceding
kernel reproduces the original wrong-interface reply. These are local results;
the existing TCP fault job retains complete current-revision hosted acceptance.

`make test-tcp6-abi` preserves all 200 address and option-copy cases and adds
sixteen name-copy checks across both musl linkages and BIOS/UEFI. Protected output
pages and aliased address/length pointers check exact bytes, faults and write
order. Axiom64 TCP copies each accessible address prefix before returning a page
fault, then publishes the length only after the address copy succeeds. The
four-byte length store remains atomic. Native comparisons retain this measured
Linux 6.17 contract and separately identify the observed Linux 7.0.0-1017-azure
length-before-address contract. All three libc profiles pass the same 216 cases
on isolated Linux 6.6, 6.17 and 7.0 kernels. Both preceding Axiom64 linkage
controls fail the partial-page regression. The evidence reader also rejects
missing name-copy observations, changed case counts and forged native ordering
profiles through serialized controls.

Native address checks distinguish the explicitly measured WSL prevalidation
profile from upstream Linux ordering; guest checks always require the upstream
minimum-length ordering. An isolated Ubuntu 6.8.0-147 kernel reproduces the
original native failure using the unchanged static client. Linux comparisons
boot separately and do not substitute for Axiom64 guest execution.

`python3 -B scripts/tests/ports_download_test.py -v` exercises the actual archive
downloader through an owned local HTTP server. Simultaneous cold callers share
one complete publication, while distinct destinations still download in
parallel. A failed transfer leaves the destination unpublished, preserves its
partial bytes and releases ownership for the next request. Existing pinned
checksum and signature validation remains in each caller.

`make test-tcp6-isolation` and `sudo -n make test-tcp6-isolation-native` check
two simultaneously open equal link-local tuples, both binding policies,
second-zone-first delivery, shared reset ownership, surviving data and
acknowledged closes. The same client checks 222 `SO_BINDTODEVICE` queries per
execution across IPv4/IPv6 TCP, UDP and raw sockets, including actual protected
pages, short capacities, shared descriptors and binding release. All three
local Linux 6.6 native and eight guest profiles pass with twenty-two original
captures and 478 reopened negative controls. A same-client, identical-root-image
old-kernel comparison reproduces the missing query before any TCP handshake.
`python3 -B scripts/tests/tcp6_isolation_prelude_test.py -v` replays the actual
UEFI reader failure, permits bounded traffic before the original readiness
request, and rejects wrong owners, excessive preludes and moved boot frames.
The original failed verdict is retained. Current-head hosted coverage remains
part of the existing TCP fault/loss job.


The same output cohort adds 128 extension-bearing sends across both adapters, raw/UDP and global/link-local scope. It retains modern/legacy header admission, ordinary-user capability rejection, original ancillary padding, actual fragmentation, DF rejection and four deferred ownership exchanges per adapter. The independent extension reader requires every original header/payload/checksum byte and rejects twenty-five damaged controls per capture. Linux socket output repeats ordinary Destination headers before the Fragment header when no Routing header exists; the generic encoder also retains its protocol layout. Forty-eight extension-chain/MTU cases and the original 54 datagrams/452 pieces run under sanitizers. All eight local guest profiles pass. All three current native linkages pass the complete output campaign, with stable original clock binding and zero drops. Earlier failed captures remain excluded. Current-revision hosted workflow coverage remains mandatory.

Another 128 sends cover type-2 Routing controls, modern/legacy ordering, distinct first-hop/final addresses, transport checksums, fragment placement and copied deferred output after every owner closes. The independent routing reader rejects twenty-nine damaged controls per capture. All sixteen guest captures pass independent inspection and both actual images are reopened. The producer initially reported a checker failure because a port-number substitution also changed its 50 ms threshold to 52 ms. The corrected reader accepts the unchanged original captures and rejects a 49 ms observation; original failed receipts remain retained. No kernel, client, packet clock or observation interval changed.

The complete output client also emits 256 local extension observations. `make test-ipv6-output-contract` compares all three native and eight guest profiles with a source-bound fixture captured from an actual complete Linux 7 execution and rejects 143 damaged logs. The earlier 480-row scalar contract remains required. The current native and guest executions also pass the full strict scalar contract. Earlier native clock failures remain rejected. Complete incoming Routing/Mobile IPv6 behavior remains required.

The same output cohort adds 160 sticky-header sends and 1,024 local sticky observations without removing earlier cases. `make test-ipv6-output-contract` runs the scalar, extension and sticky comparisons. The latter two use separate frozen observations from actual complete Linux 7 clients, with shared execution/source/product admission. They reject 143 and 176 changed logs across eleven profiles. The sticky packet reader adds 35 damaged controls per capture; all five output phases require 131 per capture. Its queued sends retain the complete fifty-millisecond rejection intervals and ownership exchanges. The earlier campaign retains its glibc and dynamic-musl clock failures. All three current native linkages pass original packet-clock checks with zero drops, and all eight current guest profiles pass. The current sticky fixture comes from a fresh complete Linux 7 execution; all 1,024 observation rows remain byte-identical. The output target runs two VM workers with every profile and the unchanged 120-second per-guest deadline. The preceding hosted four-worker dynamic profiles timed out; full current-revision hosted validation remains required.

Production host checks also exercise routed PMTU retention and SRH error ownership on both adapters, including zero/one/two remaining segments, TLVs, final versus wire destinations, invalid-SRH fallback and first-Routing-header selection. The full host, codec, reassembly, fragmentation and PMTU tests run under address and undefined-behavior sanitizers. Actual Linux 7 and four static guest firmware/transport cells separately check learned first-hop connection metrics and fresh-path error delivery. Cached Routing output is checked by `make test-ipv6-cached` and `sudo -n make test-ipv6-cached-native`, included in the existing output targets. The 128-send/128-local-error cohort compares retained host routes, live PMTU exceptions and fresh lookups across both adapters/scopes/transports, with exact copied headers, pseudo-header checksums, peer/getter state, traffic-class invalidation, extension-adjusted local error information and original ancillary bytes. Each capture rejects and replays 26 damaged controls. Three native profiles and eight guest profiles pass; original native clocks qualify with zero drops. Full fifty-millisecond PTB observations remain unchanged. The same complete client runs on Linux 7; reference VM execution supplies no native timing qualification. The broader current native error-queue and ten-minute-expiry regressions complete their clients but fail original clock binding; those campaigns remain rejected. Full current-revision hosted acceptance, native error/expiry timing and all original IPv6 requirements remain required.


Ownership observations now remember the identities already conflicted in the
current trial. A Linux dump may publish a tentative replacement while still
reporting its retiring predecessor as tentative. The client selects the single
unconflicted owner and still rejects duplicate or multiple fresh candidates.
The final exhaustion inventory still requires all four failed permanent owners.
Each ownership control record is formatted completely and emitted with one
checked write, so a kernel diagnostic between output calls cannot split it.
All 48 guest and 24 native ownership profiles pass with these changes. Independent
readers reopen eight images and 144 captures, reject 2,616 guest damage cases and
48 changed native packet-clock copies, and retain all original timing, metadata,
latency and loss checks. The original interrupted record and earlier ambiguous
inventory remain failed and unchanged.

The configuration evidence upload checks whether its path-descriptor producer
ran. An earlier failed step can skip that producer without causing a second
missing-files error. When the producer runs, missing evidence remains an error.


`make test-ipv6-device-inventory` compares twelve guest profiles with the complete
measured Linux device inventory. `sudo -n make test-ipv6-device-inventory-native`
runs the three native linkages in isolated namespaces. The same client records
twelve administrative/MTU states and 48 complete raw netlink transactions per
execution. Direct and dumped AF_UNSPEC/AF_INET6 replies retain exact interface
flags, MTU, scope presence and retained/inherited generation attributes.

Six source-bound native executions on Linux 6.17/7.0 and all twelve guest profiles
pass. Independent readers open two actual guest images, parse all 864 raw
transactions and compare 1,080 observations. The client takes its existing ordinary
netlink query before the ioctl snapshot: Linux synchronizes pending carrier work
during that query. An earlier immediate ioctl snapshot observed 0x1003 before the
following netlink reply reported 0x11043; its original log remains rejected. The
earlier guest's eight low-MTU EMSGSIZE replies also remain rejected. No failed
producer was repeated unchanged.

`python3 scripts/tests/ipv6_device_inventory_test.py --archive build/device-inventory-damaged.zip -v`
reopens the actual Linux record and both original failures, and archives/reopens
nine damaged variants. Coherent flag/MTU changes, changed raw or serialized
sequences, request-family changes, missing queries/replies/completion and an
administratively down device reporting RUNNING all reject. The current reader
replays all eighteen original profiles and rejects 162 archived changed records.
These checks establish device ABI behavior; they do not establish DAD wire clocks.
The sanitizer model separately exercises both query layouts, acknowledgments,
unavailable scopes, exact flags, required MTU fields and restored defaults.

`python3 scripts/tests/packet_protocol_test.py -v` checks actual packet demultiplexing
under sanitizers with retained captured bytes. `sudo -n python3 scripts/packet_protocol_native.py`
compares the packet client's `protocol-selection` mode across all three native
linkages in separate network namespaces. It retains both exact Ethernet exchanges,
loss counters, raw captures, original clock receipts, source manifests and actual
clients under `build/packet-protocol-native`. The existing native TCP/PMTU evidence
artifact retains that directory. This comparison checks protocol selection and
receive metadata; it does not establish native packet-clock timing acceptance.
The complete 46-boot Ethernet matrix also requires a protocol-specific listener
to receive its first actual incoming reply on every ordinary adapter. Existing
frame counts, wrap, fault, pressure, timestamp and deadline gates remain required.

`python3 scripts/tests/packet_protocol_observation_test.py -v` reopens four actual
Ethernet logs covering two and eight ordinary adapters, a malformed-completion
case and a transmit-pressure case. It requires the exact ordered numeric protocol
queries and one pass per selected ordinary interface, with no such records in
fault or pressure modes. Sixteen serialized and freshly reopened changes reject.
The complete changed-kernel Ethernet campaign passes all 46 original boots; its
stricter reader reopens the same successful executions and rejects 376 archived
changes without repeating a guest. Independent checks also reopen all 34 actual
images. Three native profiles retain six independently inspected captures and
reject twelve reopened protocol-metadata changes. Complete affected-device and
current-source hosted acceptance remain required.

The changed-kernel device requalification passes all 180 guests and 45 native
profiles on each of Linux 6.17 and Linux 7, with thirty opened images, 540 original
captures, 432 exact conflict-delivery receipts and 5,862 archived rejected
corruptions. Replaying the shared clock helper produces identical audits for all
270 profiles. All 46 original Ethernet logs and 388 guest/native metadata controls
also reopen successfully against unchanged executable dependencies.

`sudo -n python3 scripts/tests/tcp_packet_observer_test.py` exercises the actual
ICMP, PMTU and pressure C observers with real Ethernet frames, including packets
arriving after collector join. `python3 scripts/tests/tcp_capture_link_test.py`
requires complete native or guest profile groups, reconciles non-IPv4 receipts
and freshly extracts eleven damaged records per adapter. The existing TCP evidence
artifact retains these controls and observer products.

All 42 local TCP profiles pass across the three families and two pinned native
kernels, with six opened guest images and 84 captures. Full-profile readers reject
1,940 archived and freshly reopened corruptions. The ICMP native clock reader
checks dequeue order and both independent packet observation points while keeping
the guest packet-order requirement and original application windows. Run
`python3 scripts/tests/tcp_icmp_observer_clock_test.py --archive build/icmp-observer-clock-damaged.zip -v`
to reopen the actual ordering example and four damaged variants. Separate native
clock checks reject 720 changes across the 36 native captures. Original failed
producer and reader epochs remain preserved. Complete current-source hosted and
feature acceptance remain required.

`make test-udp` retains both actual images, original compile/provider inputs, commands,
logs and sixteen passive captures under `build/udp-wire/`. Its independent reader
checks the entire controlled wire scenario and the original guest result gates;
its damaged copies preserve the positive originals. The existing network evidence
artifact retains this directory. Use `python3 scripts/udp_capture.py build/udp-wire` to reopen the evidence, with
`--input-root` when corresponding sources are elsewhere. The quick actual-capture
fixture check is `python3 scripts/tests/udp_capture_fixture_test.py --archive build/udp-fixture-damaged.zip -v`.
The public controller passes all eight local profiles. Its reader opens both images,
checks sixteen captures and 1,709 frames, and rejects 1,370 archived and freshly
reopened changes: 976 physical, 372 profile and 22 input controls. The quick fixture
adds 244 archived actual-data controls. An invalid clock fraction and an unrelated
image-directory copy were first accepted and preserved, then rejected after the
reader correction. The same original successful guests are reopened; original
packet times, counts, drop gates and deadlines stay unchanged. Complete current-source
hosted and wider feature acceptance remain required.

## IPv4 multicast diagnostics

`make test-ipv4-multicast` exercises the production membership and IGMP module
with address/owner bounds, shared interests, close, retryable queue admission,
queries, source-list bounds, MTU 68 report splitting, legacy compatibility, and
link transitions under address/undefined-behavior sanitizers.

`sudo python3 scripts/ipv4_multicast_test.py --native --directory build/multicast-native`
runs the shared C client against native Linux in an isolated network namespace
with two TAP interfaces and loopback. The same client checks queued TCP
multicast flag snapshots, independent listener/child changes and real echo
after listener close. `python3 scripts/ipv4_multicast_test.py --directory build/multicast-guest`
runs it through guest virtio-net and e1000. Each directory must be new. It retains
the complete public source, executable, compile inputs, packets, and logs; guest
runs also retain their own kernel, initramfs, and ISO. Native captures keep
original kernel timestamps, independent monotonic receipts, and drop counts.
Supported native Linux references additionally retain the actual kernel
configuration before and after every capture interval. The one-second IGMP
query schedule is enumerated over 64,000 jiffy/delay combinations: the longest
is 1.065 seconds, followed by the original ten-millisecond observer allowance.
Only validated native proof selects 1.075 seconds. Guests and missing native
proof retain 1.01 seconds. Changed configuration, kernel identity, bounds,
schema or allowance fails validation. Eight host regressions retain the original
late packets and distinguish diagnostic guard inputs from actual runtime proof.

`python3 scripts/ipv4_multicast_capture.py build/multicast-guest` independently
reopens the retained evidence. The complete local cohort covers three native libc/linkage profiles and eight
guest linkage/firmware/transport profiles. Run it with
`sudo -n python3 -B scripts/ipv4_multicast_test.py --matrix --directory build/ipv4-multicast-evidence`.
Then run
`sudo -n python3 -B scripts/ipv4_multicast_evidence.py build/ipv4-multicast-evidence --output build/ipv4-multicast-audit`.
Audit output needs a Linux filesystem with POSIX ownership and modes.
Guest fixture preparation returns the shared `build/rootfs-network.cpio` to
the build directory owner and group, preserving its previous permissions even
when preparation fails. Later unprivileged guest tests can rewrite it. Run
`sudo -n python3 -B scripts/tests/ipv4_multicast_fixture_owner_test.py` for real
root-to-unprivileged replacement checks, failure propagation and first creation.
The audit exports the actual complete source into root-owned nonwritable inputs,
reopens all eleven cases normally and as UID 65534 in an isolated network
namespace, and requires identical decisions. Twenty-five freshly serialized
packet, clock, process, compilation, executable and actual-image controls must
fail for their intended reasons. Original bytes, owners and modes stay unchanged.
Only verified disposable audit copies are removed after success; failures retain
their inputs and logs.

The existing build job requires the production multicast sanitizer target. The
existing network job requires the complete cohort and protected evidence audit;
its artifact retains all original sources, products, images, captures, native
clock receipts and rejection controls. Fresh hosted qualification and the wider
multicast contract remain required.

### Source-filter reports

The source-list, aggregate, report counter and production host checks are
`make test-ipv4-source-filter test-ipv4-source-aggregate
test-ipv4-multicast-source-host test-ipv4-source-reports
test-ipv4-multicast-source-wire-host test-ipv4-multicast-queries`. They cover transactional admission,
hidden contributors at final close, output refusal, legacy retries, query
selection, MTU changes and separate mode/source retransmission obligations.

The shared C wire client performs actual socket operations on both interfaces.
Choose `delivery`, `settled`, `queries`, `mtu`, `overlap` or `query-bounds` with `--source-case`:

```sh
sudo -n python3 -B scripts/ipv4_multicast_test.py --suite source --source-case mtu --profile dynamic --firmware uefi --transport legacy --directory build/multicast-source-mtu
PYTHONPATH=scripts python3 -B -m ipv4_multicast.source_capture build/multicast-source-mtu
python3 -B scripts/tests/ipv4_multicast_source_evidence_test.py --directory build/multicast-source-mtu --output build/multicast-source-mtu-controls
```

Use a fresh directory for each execution and control set. Audit inputs and
outputs must stay separately below `build/`; protected readback requires a
Linux filesystem with POSIX ownership and modes. Add `--native --profile
native` for glibc, or use `--native --profile static|dynamic` for the musl forms.
A producer completion is diagnostic; the independent reader must also accept
the original source, actual products, packets and clocks.

Physical pre-action barriers assign reports to the correct operation. Normal
post-action barriers retain three complete seconds on both interfaces. The
overlap case instead releases stages 1 and 5 only after a real first report,
then changes that filter while retransmissions remain pending. Its five other
stages keep the complete windows. Negative controls reject a missing report,
an acknowledgment preceding its report and a zero-duration full observation.

The MTU case configures and reads back MTU 68 and source capacity 64, checks
complete INCLUDE splitting and stable truncated EXCLUDE reports, then changes
the live MTU to 1500 and requires the full 64-source query response. It restores
the original source policy of 10 before completing. Serialized controls retain
valid packet checksums while removing fragments, repeating sources, exceeding
the actual MTU, splitting EXCLUDE output or forging restoration observations.

The delivery case uses eight independent raw/UDP receivers on each adapter:
INCLUDE(source A), EXCLUDE(source A), an unjoined multicast-all receiver and an
unjoined receiver with multicast-all disabled. Both sources are injected as
actual checksummed UDP packets. Each phase also sends real raw and UDP output.
The client retains duplicate descriptions, closes originals, closes final
owners, creates fresh descriptions, rejoins and changes multicast-all. The
reader matches every received byte and source/port against the original wire
packet and requires complete 200 ms quiet windows, full three-second physical
observations and exact independent queue masks.

Run the complete six-case cohort and protected root/ordinary-user readbacks:

```sh
sudo -n env PYTHONPATH=scripts python3 -B -m ipv4_multicast.source_matrix build/ipv4-source-evidence --produce
sudo -n env PYTHONPATH=scripts python3 -B -m ipv4_multicast.source_protected --directory build/ipv4-source-evidence --output build/ipv4-source-audit
```

The default contract requires all 66 profiles: three native linkages and eight
guest linkage/firmware/transport combinations per case. Each linkage uses one
byte-identical common C executable. The reader binds the original cohort
kernel, kernel sources, both C implementation files, header, init, shell and
native/musl runtimes to preexecution fingerprints. Eight serialized cohort
controls include internally consistent altered ELF/loader images and source
archives, which individual-case readers accept but cohort binding must reject.

The retained preceding-kernel local audit accepts all 40 guests: 1,250 reporting records,
176 queries, 496 complete reporting windows and 32 first-packet barriers, plus
256 delivery sends, 736 receives, 128 complete quiet windows and 128 complete
delivery wire windows. Root and UID 65534 each reject 60 reporting, 36 delivery
and eight cohort controls, preserving original bytes, owners and modes.
The overlap regression replays both captured legal report/call interleavings;
counterfeits still reject missing retries, extra old-mode/final-block copies,
wrong directions and two retries bundled into one physical packet.

Four of the fifteen preceding local native captures qualify. Eleven original native
captures retain their failed stable clock-offset checks. For this diagnostic
situation only, explicitly pass `--domain guest` to the cohort and protected
readers; production always attempts all 66, default verification still requires
all 66, and the scoped result records full native/guest acceptance as false.
CI uses the default full contract in the `ipv4-source-filters` test entry.
Its 75-minute deadline and original 100-second profile deadlines remain.
The existing network entry previously took 63 minutes; the additional suite
runs separately and retains all original entries. Current-source hosted timing
and full native/guest acceptance remain to be measured.

`query-bounds` requires actual MTU 1500 readback on both interfaces. It injects
65 unrelated sources into an INCLUDE filter, a checksummed query with four
additional octets, 65 duplicate sources, and EXCLUDE queries with 65 and 366
unblocked sources. The independent reader verifies the complete original query
and response source lists, all checksums and every physical output piece.
The measured native EXCLUDE difference remains explicit; guest responses follow
RFC 9776 Table 5. All eight phases retain full three-second observations.

The query store has a shared 256 KiB budget. Sanitized checks exercise complete
IPv4-sized input lists, sorted unions, caller-buffer ownership, peak budget
accounting, allocation failure, cursor preservation and teardown. A failed merge
preserves an accepted query; it cannot convert the response into a full-group
record. The original production-module replay fails before and passes after
the correction for both 65-source filters and valid trailing octets.

The expanded protected audit requires 132 serialized controls per identity:
12 settled, 16 query, 19 MTU, 21 overlap, 20 query-bounds, 36 delivery and eight
cohort controls. Reporting readback now checks actual firmware boot text and
the recorded paired-device/virtio transport command. The original serialized
firmware/transport counterfeits were accepted before these checks; both now
reject. The six-case audit on the new kernel accepts all 48 guest profiles: 1,440 reporting
records, 256 actual queries, 624 complete reporting windows and 32 first-packet
barriers, plus 256 delivery sends, 736 receives, 128 complete 200 ms quiet windows and
128 complete three-second delivery windows. Root and UID 65534 independently reopen the
original evidence and each reject all 132 serialized controls. 7 of eighteen local
native captures qualify. The remaining original native failures stay rejected; the
explicit guest diagnostic result does not establish full native/guest acceptance.
Default production and hosted verification require all 66 profiles. Complete
current-source hosted qualification and broader multicast behavior remain required.
Diagnostic controls use an independently qualified native delivery capture from the same
cohort. Every original native outcome remains recorded; the default full contract still
requires all eighteen native profiles.

### Raw UDP sockets and source-filtered loopback data

The IPv4 limits fixture requires rejection of a UDP stream socket, successful raw UDP
creation, exact socket type/protocol queries and final close. All eight normal/fault
BIOS/UEFI modern/legacy IPv4 profiles pass on the new kernel, retaining both adapters
and the complete ten-minute learned-limit observations.

`make test-ipv4-paths` includes a production socket/output regression that fails
with the original implementation: the IPv4 packet uses ICMP despite a UDP raw
description. The corrected path checks protocol-specific output and receive
fanout, address/device/peer isolation, raw delivery before UDP validation and
protocol-matched ICMP errors under both sanitizers.

Build the shared runtime client with:

```sh
make build/ipv4-raw-udp-native build/ipv4-raw-udp-static build/ipv4-raw-udp-dynamic
```

Native execution requires a private network namespace with loopback up. The
same per-linkage executables run in retained Linux reference initramfs files
and Axiom64 RAM-root fixtures. The client checks protocol/name metadata,
ignored socket-address ports, option-fault ordering, independent raw listeners,
zero and maximum raw payloads, malformed UDP input, INCLUDE/EXCLUDE data,
multicast-all and duplicate/final-description lifetime. Every quiet observation
keeps its full 200 ms duration. Guest deadlines remain 40 seconds.

The retained comparison corpus contains nine successful native and four guest
profiles, plus the original unsupported guest and down-loopback Linux control.
For a complete exported corpus below `build/`, run:

```sh
python3 -B scripts/ipv4_raw_udp_evidence.py build/raw-udp-corpus
python3 -B scripts/tests/ipv4_raw_udp_evidence_test.py --directory build/raw-udp-corpus --output build/raw-udp-controls
```

Protected root and UID 65534 readbacks agree on 2,860 raw operations, 299 packet
observations, 624 complete quiet windows and 91 source-filter phase executions.
The original 79-operation client also passes in all three native and four
guest profiles. Twenty-five serialized controls reject wrong protocols,
addresses, payloads, copy errors, shortened observations, missing maximum
packets, stale source interests, incomplete original checks and changed source,
executable, loader, kernel and image products. Same-linkage executables remain
byte-identical, and all comparisons use the same client source. Native
initramfs fingerprints and every guest runtime product stay bound to the actual
preexecution records. A previous reader accepted changed ELF padding and a
changed dynamic loader in a matching image; both original counterfeits are
retained and rejected after correction, without repeating runtime producers.

These tests establish the listed loopback socket/data cases. They do not
qualify Ethernet raw UDP, native IGMP packet clocks, the new kernel's complete
source-report matrix or full current-source hosted acceptance.

The TCP device observer selects its owned IPv4 output-copy breakpoint within
`ipv4_poll`, next to the current queue item lookup. It rejects a missing or
ambiguous location before arming. Run
`python3 scripts/tests/tcp_device_pending_site_test.py` to check competing route
guards, unrelated poll guards and absent or duplicated queue sites. The existing
physical removal, copied bytes, owner reclamation, surviving stream and clock
checks remain required.

## IPv4 receive-control comparison

`sudo make test-ipv4-receive-controls` runs the same C client in three isolated
Linux loopback namespaces and four static/dynamic BIOS/UEFI guests. It retains
the corresponding source, actual programs and compile manifests, kernel,
initramfs, ISO, QEMU commands and complete logs under
`build/ipv4-receive-controls`. Each profile includes 1,395 receives, 468 real
control-page fault cases, 1,344 payload/vector, source-name and result-header
cases, and four descriptor/accepted-child lifetime cases. The reader retains
the original control comparisons and checks each result-copy prefix against
the actual queued packet. It rejects 28 serialized observation alterations and
16 serialized changes to the independent probe, its source, program and
execution records. All altered inputs are reopened before the model checks.

A separate actual-socket probe runs before the libc clients and records both
`recvfrom` and `recvmsg` source/length faults. Its copied executable, source,
command and complete-source fingerprints are saved before execution. The
reader checks that record against the original process result and log. It
accepts only the address-first or length-first order actually observed on
that kernel. There is no command-line option to force the model. Local
validation includes all three libc profiles on Linux 6.6, 6.17 and 7, with
both store orders observed. The guest follows the Linux 7 length-first order.
Root and ordinary-user readbacks bind all four actual ISOs, initramfs files,
programs, loaders, compile manifests and source snapshots without changing
the original bytes, owners or modes.

Accepted-child checks observe actual listener readiness before changing the
listener, so the child snapshot belongs to an established server connection.
The check does not infer server progress from client-side `connect` completion.
This loopback comparison does not establish further ancillary options,
physical-device failure lifetimes or complete networking support. The separate
Ethernet comparison below covers interface metadata and queued address/route changes.
The existing network CI entry runs this comparison alongside its prior tests.

Ethernet metadata acceptance must retain original packets from virtio-net and
e1000, together with matching native namespace traffic. It must distinguish
the actual ingress and destination from reverse-route source selection, and
prove that queued packets retain those values when addresses or routes change.

## IPv4 Ethernet receive metadata

`sudo make test-ipv4-receive-wire` compares three isolated native libc profiles
with eight static/dynamic BIOS/UEFI guests using modern/legacy virtio-net and
e1000 together. Each profile receives 156 actual IPv4 packets. Cases cover UDP,
raw ICMP and raw UDP with paired UDP delivery, arrival-time packet-info
selection, varied TTL/TOS, primary and secondary addresses, a separate prefix,
limited and directed broadcasts, multicast reverse-route selection, ingress
fallback and delivery to another interface's local address.

The client observes the queued payload before removing an alias or prefix, or
replacing a reverse route. It retains 180 actual netlink inventories per profile
around arrival, mutation and restoration. The reader decodes those original
dumps and both Ethernet captures, checks every packet checksum and barrier,
and compares all control bytes with Linux. Only actual ingress indices are
mapped between systems. It opens the boot images and checks their kernel,
initramfs, client, loader and script against retained products and sources.

Evidence stays under `build/ipv4-receive-wire`. The independent reader can be
run again with eleven `--case` directories:

```sh
python3 -B scripts/ipv4_receive_wire_contract.py --help
```

The complete local cohort passes. The reader rejects 27 serialized changes
to receive metadata, packet/barrier records, inventories, compile inputs and
boot products while preserving all original input bytes, owners and modes.
This comparison does not qualify IGMP timers, every receive-copy fault, output
ancillary controls, hardware removal or complete networking support. Existing
multicast timing and full workflow requirements remain separate.

Native path-MTU, error-queue and cached-route comparisons place each profile's client, TAP coordinator and independent collectors on one recorded CPU before creating collector threads. Separate profiles select different available CPUs where possible. Linux can wake an all-protocol packet socket on another CPU before delivering the same frame to the collector; the next client request can then enter the capture queue ahead of its preceding acknowledgment. The private fixture affinity prevents this race while the host retains its SMP kernel. Guest scheduling, client arguments, kernel timestamps, real observation windows and independent rejection rules retain their existing behavior. Earlier inverted captures remain rejected.

`sudo -n make test-native-ipv6-capture-order` runs an actual all-protocol C packet client through all three profile CPU selections. Each exchanges 8,192 barrier pairs, binds all original frames to independent clock receipts and rejects serialized reordered, missing and damaged packets. Every 64 pairs, the coordinator waits for the actual final acknowledgment receipt before continuing, bounding the collector backlog while preserving every packet and the existing receipt deadline. The probe uses the host C runtime; the complete IPv6 suites separately retain their three actual libc linkages. The existing error-queue target includes the regression, and the existing IPv6 artifact retains its sources, program, ownership records, captures and controls.

Administration and rotation fault campaigns share the disposable NBD launcher. Each start retains `backend-startup.json` with its exact command, executable hash, socket and trace state, elapsed observation and unchanged five-second bound. On timeout or early exit, the report includes the actual process state before termination and host CPU/memory pressure. Launch errors close the log; failed starts remain failures and grant no retry. The startup regression exercises both callers with actual NBD sockets, early-exit children, stopped children and missing executables. The observed administration baseline failure had an empty backend log and no process report; its cause remains unproven.

The result-fault extension retains all original ancillary and lifetime cases. It adds guarded payload/vector output, invalid or incomplete vector/header input, out-of-range addresses, NULL/truncated/signed source capacities, both orientations of protected message fields, and dequeue/peek observations. All 1,344 cases pass per profile across nine actual Linux comparisons and four guests. The original guest kernel failed 696 cases per guest; its programs, source, images and logs remain retained. The shared copier also passes the existing eight-guest/three-native IPv6 comparison, all 854 cases and 240 rejection controls. Every existing CI job, scenario and real deadline remains required.


## IPv4 send-control comparison

`sudo make test-ipv4-send-controls` runs the same 384-case C client in three
isolated Linux loopback namespaces and four static/dynamic BIOS/UEFI guests.
Each execution retains all 768 selected and baseline observations: raw ICMP,
raw UDP and UDP, named and connected sends, complete ancillary bytes, protected
input pages, error ordering, automatic binding, shared defaults and actual
52-byte packets. The original 30-second native and 120-second guest bounds remain.

`build/ipv4-send-controls` retains the complete public source archive, actual
programs and compile manifests, native namespace identity and live libc maps,
runtime provider bytes, all four guest images and initramfs archives, original
commands, process results and logs. The independent reader opens each image
and binds its kernel, client, loader and boot script to the retained products:

```sh
python3 scripts/ipv4_send_controls_contract.py --directory build/ipv4-send-controls --output build/ipv4-send-controls-readback.json
```

Twenty-one serialized damaged-input controls cover the seven original log
mutations plus source, executable, compile, linkage, runtime provider, firmware,
kernel, image, initramfs, loader, deadline and complete profile-grid binding.
These loopback checks supplement the required physical-interface comparison.

## IPv4 Ethernet send controls and route ownership

`sudo make test-ipv4-send-wire` runs three native libc profiles and all eight
static/dynamic BIOS/UEFI modern/legacy guests on virtio-net and e1000. Each
profile retains the original 100 cases and adds 36 route-lifetime cases: 136
cases, 816 physical barriers, 72 ordinary sends, 60 sleeping sends and four raw
memory-pressure cases. Twenty-eight full three-second retirement observations
and the original 180-second process, syscall, barrier and socket-timeout bounds
remain required. Payload, control, header, vector and descriptor mutations
distinguish admission-time metadata from later copied payload bytes.

Explicit host routes, automatic prefixes, connected UDP and forced-interface
fallbacks face preference changes, deletion/recreation and real administrative
down/up. Pressure fills use the opposite adapter while the tested send remains
asleep. Raw route/address inventories and independent Ethernet captures verify
source selection, held ownership, silent route retirement, fallback retention
and current defaults. Native output is recorded separately for each adapter
and send case. Linux cache replacement can move a held destination away from
the retired FIB cache, so sends on one kernel may differ. Every emitted native
packet still requires its original route, source, metadata and payload, followed
by the required later baseline. Guest FIB retirement must discard old sends.

Native source and peer devices occupy separate private network namespaces.
Peer devices stay up during source down/up, with recorded reciprocal indices,
software checksums and disabled segmentation offload. Capture clocks and drop
receipts retain their original guards. Clock-discontinuous runs remain failures.
`build/ipv4-send-wire` retains original captures, transport frames, logs, full
sources, actual programs, manifests and all boot images. Independent readers
reopen these inputs and reject 32 guest evidence controls and six native peer
topology controls. The existing receive comparison and normal/fault IPv4 matrix,
including full path-MTU observation intervals, remain required.

`python3 -B scripts/tests/ipv4_send_capture_test.py -v` reopens the original
mixed native capture and its complete C records, physical frames, transport
observations and independent clock receipts. Serialized negative cases require
rejection of changed retained-packet TTL or payload, a missing later baseline,
capture loss and retired guest output. The full fresh native and guest cohorts
remain required alongside this captured-data regression.

The Ethernet retirement observer requests three seconds plus the reported monotonic clock resolution to cover coarse-clock quantization. Independent capture readers still require at least three complete seconds; process, syscall and barrier deadlines are unchanged.

Native IPv4 packet clients and both independent collectors share one recorded allowed CPU. The existing packet-profile selector rotates libc profiles across available CPUs before creating collector threads. Readers verify the private parent namespace, actual task and client affinity; three serialized CPU/namespace controls supplement every original receive and send control. The existing IPv4 source-filter CI job also runs both complete send cohorts, with every original scenario and timing bound retained.

## IPv4 packet options

`make test-ipv4-options-model` runs the production option engine with AddressSanitizer
and UndefinedBehaviorSanitizer. Retained Linux 6.6.87.2 and 7.0.14 observations each
contain 14,220 setter/query results. The current policy requires `CAP_NET_RAW` for
valid source routes; syntax errors precede permission errors, and either failure
preserves the preceding value. The model also retains 214 receive-parser cases. Twenty thousand malformed
inputs also exercise value preservation and output bounds. Receive comparisons retain
the original packet bytes and actual timestamp bounds; source-route packets rejected
by admission policy cannot establish parser results. Accepted completed routes still
check return-route reversal. This command does not need root or a guest build.

`sudo make test-ipv4-options` runs two C clients in three native linkage profiles
and four static/dynamic BIOS/UEFI guest profiles. Each socket-client execution checks 42,660 option
observations, root and ordinary credentials, fault ordering and sixteen actual
loopback packet exchanges. Those packets exercise processed route/timestamp slots,
independent return controls, real UTC timestamps and per-message replacement. Native
executables wait on a pipe while their actual executable mappings and provider bytes
are retained; guest programs run without this observer. The client reads serialized
controls directly so a trailing empty return control is checked with every libc.
Before native execution, two fixed source-route probes on an inherited descriptor
identify the observed ordinary-caller policy. They select one complete retained
table; unknown or inconsistent results fail. Guest executions always use the fixed
current-policy table. The independent reader verifies both table contents against
the original source archive and rejects damaged policy proofs. All vectors remain
required on both native policy families.

The TCP client adds 36 root/ordinary cases for closed-port resets, accepted option
snapshots and duplicate-FIN replies in retained and compacted TIME-WAIT states. It
replays the actual original FIN with a recomputed transport checksum, then inspects
the actual kernel reply. Creation and `SO_PROTOCOL` checks cover all 261 supported
raw protocol numbers. `IPPROTO_RAW`/`IP_HDRINCL` remains unfinished. Raw observations
retain Linux's original IP checksum after local option processing; the client
reconstructs the known zero receive slot to check that original checksum. Physical
Ethernet checksum acceptance remains separate.

Both clients run in each of the four guest images. The runner retains both audited
ELFs and their compile inputs while sharing the kernel, loader and boot. Native
execution has six processes across the three linkage profiles. No extra CI jobs or
guest boots are added for the TCP client.

The runner also reopens all four actual ISOs and checks their kernel, complete
initramfs, both clients, loader and oracle table. Its independent reader binds the
complete source archive and native provider mappings, checks original TCP headers,
SYN ownership and replayed FIN sequences, and rejects 98 reopened damaged logs.
Several controls repair packet checksums so an incorrect sequence, option value or
ownership cannot pass merely by carrying a valid checksum. The original evidence
can be checked again with `python3 scripts/ipv4_options_evidence.py build/ipv4-options`.
To retain fresh damaged controls, run `python3 scripts/ipv4_options_evidence_test.py build/ipv4-options --directory build/ipv4-options-controls`.

The runner writes corresponding source, build inputs, native provider mappings,
programs, boot products and complete logs under `build/ipv4-options`. An existing
directory is refused. `python3 scripts/ipv4_options_capture.py --output build/ipv4-options-native.json.gz` captures a new root/ordinary setter corpus without
sending packets or overwriting prior observations. The installed fixture records its
actual kernel; it does not establish equivalence with every Linux kernel.
`sudo python3 scripts/ipv4_options_receive_capture.py` records a new receive corpus
inside its own network namespace, enables source-route admission there, and verifies
that the parent namespace's network settings remain unchanged.

The existing Ethernet fragment client now keeps twelve input and 45 output cases per
interface. Six input cases add record-route, timestamp, mixed options, reverse arrival
and differing fragment header lengths. The 24 output additions cover complete 65,535-byte
datagrams with forty option bytes, minimum-MTU fragmentation, copied and non-copied
options, exact device limits, oversized rejection and description changes after send.
Received packet bytes and application clock intervals remain in the log. The independent
`ipv4_options_fragment_capture.py` reader checks both directions, every reassembled
payload byte and the original or completed header checksum. It reopens 23 damaged
packet/log controls, including changes with repaired network and transport checksums.

Native fragment comparisons give each independent reader its own process. Each reader
retains at most 10,000 complete frames and 16 MiB of packet bytes, then serializes them
after its receive queue drains. Every frame keeps its actual kernel timestamp and
the paired clock observations made immediately after `recvmsg`. The original packet
loss checks, one-second reader-latency guard, one-second reader shutdown and protocol
deadlines remain required. This avoids making burst capture compete with Python
packet validation and receipt formatting.

The ordinary IPv4 guest workload and full native `--fragments` command include these
cases while retaining real sixty-second fragment expiry and ten-minute PMTU lifetime
observations. The client option `--fragment-datagrams` provides focused development
diagnostics for the twelve input and 45 output cases. It does not establish expiry,
PMTU, complete firmware/device/provider or full-feature acceptance.

The option-specific commands qualify their stated model and loopback scope. Ethernet option headers,
fragment copy bits, source-route receive policy, broader TCP responses, PMTU quotes and
blocking/output lifetime cases remain necessary for complete packet-option acceptance.
The existing receive/send-control and full networking cohorts remain required.
