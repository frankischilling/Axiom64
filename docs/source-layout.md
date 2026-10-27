# Source layout

Kernel sources and headers are grouped by subsystem. Includes name the module, such as `fs/vfs.hpp` or `drivers/virtio/queue.hpp`, from the `kernel/include/` search root.

| Folder | Contents |
| --- | --- |
| `kernel/arch/x86_64/` | CPU setup, counter clock selection, RTC I/O, assembly entry, linker layout |
| `kernel/boot/` | Boot protocol, kernel startup, and root selection |
| `kernel/core/` | Freestanding runtime, diagnostics, and counter arithmetic |
| `kernel/core/random/` | Cryptographic primitives, entropy pool and generator state |
| `kernel/firmware/` | Bounded ACPI table parsing and QEMU generation-ID discovery |
| `kernel/abi/linux/` | Linux syscall dispatch and ABI structures |
| `kernel/mm/` | Physical and virtual memory, mapping/protection and heap admission limits, grow-down stacks |
| `kernel/process/` | Tasks, scheduling, CPU accounting, process resource tables, signals, futexes, child-event waits and checked executable argument capture |
| `kernel/fs/` | VFS, RAM filesystems, procfs process identity and IPv6 configuration controls, xattrs and advisory file locks; ext2 storage and EA codec have their own subfolder |
| `kernel/security/` | Task credential transitions and bounded file capability decoding |
| `kernel/io/` | Retained blocking I/O requests and captured vector bounds shared with IPv6 error receives |
| `kernel/ipc/` | Sockets, event counters, readiness, shared memory |
| `kernel/net/` | Ethernet interfaces, interface/route ioctls, and Linux raw packet sockets |
| `kernel/net/ipv4/` | IPv4 routes/output, bounded reassembly, shared path-MTU limits and fragment emission, ARP cache/timers, ICMP, and Internet socket descriptions |
| `kernel/net/ipv6/` | IPv6 wire and quoted-error validation, bounded reassembly, source-fragment encoding, owned output queues, route-owned path-MTU limits, scoped address/route ownership, DAD, neighbor state, copied extended-error queues and raw/UDP socket ownership; `router.cpp` owns solicitation schedules, learned routers/prefixes, per-link advertised parameters and SLAAC lifetimes, including first-PIO refresh, stable conflict regeneration and owned exhausted-prefix cleanup; `output.cpp` snapshots inherited hop limits after route selection; nested `socket/` owns Linux controls and error-receive copying |
| `kernel/net/udp/` | UDP lengths, pseudo-header checksums, payload delivery, and transmission |
| `kernel/net/tcp/` | TCP wire/state/sender policy, socket ownership, timers, ISNs, TIME_WAIT and quoted ICMP errors |
| `kernel/net/netlink/` | Link/address inventories, IPv6 link-generation controls, route/address message validation, owned replies, and control socket lifecycle |
| `kernel/drivers/platform/` | PCI, PIIX4 power off, and current platform device interfaces |
| `kernel/drivers/block/` | Block request policy and raw I/O |
| `kernel/drivers/net/` | PCI virtio-net and QEMU e1000 adapters |
| `kernel/drivers/random/` | Virtio entropy input, completion validation and source lifetime |
| `kernel/drivers/virtio/` | Shared PCI transport and split queues |
| `kernel/include/` | Public internal headers with matching module paths |
| `kernel/tests/` | Host tests grouped by module; excluded from kernel linking |
| `userspace/init/` | Ring 3 init |
| `userspace/accounts/` | Account generations, administration, authentication, private sessions, login journals and archive rotation |
| `userspace/services/` | Persisted seed ownership, rotation and recovery |
| `userspace/desktop/` | Display sessions, Xorg and window-manager configuration |
| `userspace/net/config/` | Ring 3 address/route adapter, ownership recovery, saved profiles, and resolver metadata |
| `userspace/net/dhcp/` | Bounded packet codec, lease state, and bootstrap/UDP transport |
| `userspace/tests/` | ABI, filesystem, IPC, network, process, thread, storage, desktop, and native toolchain tests |

Make discovers kernel C++ sources recursively, excluding `kernel/tests/`. Object and dependency files mirror the source folders under `build/kernel/`. Compiler-generated dependencies select the headers that each object uses. New sources added to a module folder participate in the next build.

Userspace program targets name their source files explicitly. Initramfs dependencies include session scripts and configuration recursively, plus the native toolchain fixtures. The root-filesystem builder preserves the guest installation paths, including `/sbin/init`, `/etc/boot-test.sh`, and `/root/toolchain-test`.

Build and port helpers remain under `scripts/`; pinned dependency inputs are in the lock files and `vendor/`. Documentation belongs under `docs/`. Generated outputs, downloaded archives, private answers, local evidence, and worktrees remain in the ignored `build/`, `downloads/`, and `.local/` directories.

Installed-startup supervision uses `scripts/normal_manager_test.py`. Its `normal_ipv6_peer.py` helper owns strict validation and bounded retention of default DAD/router-solicitation frames; the existing manager and DNS peers keep their IPv4 checks.

The IPv4 resolver fixture stays in `scripts/dns_test.py`. It owns isolated initramfs/ISO inputs and per-execution source, program and packet retention; `dns_peer.py` keeps the strict protocol checks. Its boot script selects the IPv4-only test configuration before either resolver client starts.

`scripts/dns_observer.py` binds both UDP and TCP resolver driver records to
original Ethernet captures. The actual C collector lives in
`userspace/tests/net/dns/contract.h`; its regression checks both packet directions,
non-IPv4 records and packets queued after collector shutdown. The capture tests
archive and freshly reopen damaged copies of actual DNS evidence.

Controlled DAD comparisons use `userspace/tests/net/ipv6_dad.c` and its bounded netlink inventory header. `ipv6_dad_inventory_model.c` exercises the actual candidate selector. The matching `scripts/ipv6_dad_test.py`, peer, independent capture reader, native policy and damaged-evidence generator keep execution, observation and rejection checks separate. The shared native `Capture` in `tcp_fault_native.py` configures its timestamp/buffer before reception and stops new input before draining queued records; packet and clock counts still have to match exactly.

The corresponding-source bundle walks kernel and userspace folders recursively, so it includes the same sources and headers used by the build. [Testing](testing.md) describes the existing guest and host suites; [architecture](architecture.md) describes interfaces and current limits.

Device transition clients share `userspace/tests/net/ipv6_device_fixture.h`.
The ready and pending programs retain separate state contracts. Their shared
`scripts/ipv6_device_frames.py` decoder reads original physical captures; the
live peer does not supply its acceptance decisions. `qemu_capture_delivery.py`
waits for complete captured frames before guest conflict acknowledgments. Its
regressions retain an actual ordering failure and a real first-inventory ready
observation under a predefined delayed acknowledgment.

`scripts/native_ipv6_timers.py` records native kernel configuration and actual
DAD timer parameters around the device client. Its independent capture reader
uses that bounded proof only for the supported native regeneration contract;
guest timing stays separate. `scripts/tests/native_ipv6_timers_test.py` replays
an original late capture and explicitly constructed policy corruption inputs.

`scripts/native_icmp_preflight.py` owns the native fragment peer's acknowledged
UDP error setup; `native_icmp_preflight_capture.py` reopens its original packets,
clocks, rate settings and control-release receipt. The native-only C control
client is `scripts/tests/native_icmp_budget.c`; `native_icmp_budget_test.py`
retains cold/staggered/primed comparisons and independently checks their bytes.
These helpers supply no kernel or guest implementation.

`userspace/tests/net/tcp6/replies.c` supplies shared native/guest TCP reply
observations. `scripts/tcp6/replies_peer.py` owns controlled requests;
`replies_capture.py` independently checks original packets and reopens changed
evidence. The existing TCP6 runner retains source, compiler products, actual
images and complete linkage/firmware/transport matrices for this cohort.

`scripts/ports.py` serializes each archive's cold download and publication with
its own file lock. Distinct archives remain concurrent. The real local-HTTP
regression under `scripts/tests/ports_download_test.py` covers colliding writers,
parallel independent destinations and interrupted transfer recovery.

`kernel/net/socket_options.cpp` and `kernel/include/net/socket_options.hpp` own
device-name queries shared by IPv4/TCP and IPv6 raw/UDP descriptions. The single
interface hides device lookup, unbound and stale binding results, capacity
checks and ordered page-copy faults without changing destination state.
`userspace/tests/net/tcp6/isolation.c` exercises that interface through actual
syscalls while keeping duplicate scoped streams open. Its independent peer and
capture reader live under `scripts/tcp6/isolation_*.py`; the retained pre-readiness
UEFI fixture and four replay tests live under `scripts/tests/`.

## Formatting

The root `.clang-format` contains C++20 and C profiles. Kernel sources, headers, and host tests use the C++ profile. Userspace C sources use the C profile, and native C++ test programs use the C++ profile. Both preserve include order and use four spaces and a 100-column limit. Function bodies use multiple lines, and `SeparateDefinitionBlocks: Always` inserts a blank line between function, class, struct, and enum definitions. Keep one blank line between function prototypes too; `MaxEmptyLinesToKeep: 1` preserves that spacing. The Makefile continues to select C11 and C++20 for compilation.

On the Ubuntu build host, install the formatter and run these commands from the repository root:

```sh
sudo apt-get install -y clang-format-20
make format
make check-format
```

The targets cover project C/C++ sources and headers under `kernel/` and `userspace/`, plus the native ICMP control client under `scripts/tests/`. Imported headers under `vendor/` retain their upstream formatting. Set `CLANG_FORMAT=/path/to/clang-format-20` when the executable uses another name. Clang-format 20 or newer can read the separate C profile; version 20 is used for the checked formatting. CI runs `make check-format`, and the corresponding-source bundle includes the configuration.

`kernel/tests/net/packet.cpp` exercises the production packet demultiplexer with
captured bytes. `scripts/tests/packet_protocol_test.py` builds that sanitizer model.
The shared `userspace/tests/net/packet.c` listener check runs in ordinary Ethernet
boots and in the isolated three-linkage comparison under
`scripts/packet_protocol_native.py`. Native orchestration and retained evidence
remain outside the kernel and guest implementation.

`network_test.packet_protocol_observations` checks ordered numeric listener
queries and completion records for both guest and native comparisons.
`scripts/tests/packet_protocol_observation_test.py` uses unchanged actual logs
under `scripts/tests/fixtures/packet-protocol-observation/` to check ordinary,
fault and pressure modes and serialized corruptions.

`scripts/tcp_capture_link.py` reconciles non-IPv4 receipts from the ICMP, PMTU
and pressure observers against original Ethernet records. Its negative writer
preserves unrelated raw records. `scripts/tests/tcp_capture_link_test.py` retains
and freshly reopens damaged real-profile receipts; `tcp_packet_observer_test.py`
wraps the actual C collectors and injects late frames through isolated adapters.

`scripts/tcp_icmp_capture.py` checks guest packet ordering, native dequeue order
and the direction-specific relationship between driver and independent packet
timestamps. The shared clock binder exposes exact realtime metadata only when
requested. `scripts/tests/tcp_icmp_observer_clock_test.py` uses original bytes
under `scripts/tests/fixtures/icmp-observer-clock/` and archives damaged copies.

`scripts/udp_inputs.py` retains the actual static UDP client, compiler/provider
inputs and both immutable boot images. `udp_matrix.py` runs the existing eight
profiles through `udp_test.py`, which adds passive captures when an evidence
directory is supplied. `scripts/udp_capture.py` checks complete original physical
traces, profile results, commands and image/source bindings without using the live
peer's validator. `scripts/tests/udp_capture_test.py` archives and freshly reopens
physical and metadata corruptions; `udp_capture_fixture_test.py` exercises unchanged
actual captures under `scripts/tests/fixtures/udp-wire/`.


`scripts/native_address_worker.py` owns temporary host CPU-mask changes for the
native router reference. It serializes ownership, propagates command exits,
retires its child process group on cancellation and records restoration.
`scripts/tests/native_address_worker_test.py` exercises those paths against the
actual host masks. Guest clients and kernel sources do not use this helper.


TCP wire processing shares one header/option/payload implementation in
`kernel/net/tcp/wire.cpp`. Its private `wire_detail.hpp` interface is used by the
IPv6 checksum adapter in `wire_ipv6.cpp`; callers use the typed overloads in
`kernel/include/net/tcp/wire.hpp`. The two address families retain independent
fixed packet checks. The local IPv6 TCP application client is under
`userspace/tests/net/tcp6/`. `kernel/net/tcp/ipv6.cpp` owns the IPv6 stream
syscall front; both families keep the common connection/socket engine.
`net/tcp/address.hpp` defines canonical wire identities and binding overlap.
Real-interface loss recovery has paired native/guest checks; full
route/error/lifetime integration remains unfinished.
The shared connection engine selects family-specific fallback MSS without
duplicating its state machine. `isn.cpp` retains one keyed hash implementation
and separate IPv4/IPv6 tuple encodings. The IPv6 output queue accepts a transport
completion owner through `net/ipv6.hpp`; its raw/UDP adapter and transport callers
share packet storage and callback retirement. `ipv6_output_owner.cpp` exercises
that production queue's admission, copying, completion and detachment. The
`tcp6/abi.c` application checks Linux address imports, V6ONLY updates and name
copy faults; `make test-tcp6-native` runs it and the local exchange client.

IPv6 TCP quote ownership and path-MTU adaptation live in
`kernel/net/tcp/icmp_ipv6.cpp`; the connection engine retains sequence, sender
and timer policy. `kernel/tests/net/tcp_ipv6_error.cpp` exercises the actual
Ethernet/error/output path. The shared MSS lifecycle client is
`userspace/tests/net/tcp_maxseg.c`; `tcp6/mss.c` selects IPv6 without copying
its option, alias, inheritance and reconnect cases.

The IPv6 Ethernet loss coordinator is `scripts/tcp6_test.py`. Its focused
`scripts/tcp6/` package separates wire encoding, native TAP ownership, guest
boots, source/product binding, monotonic packet observations and independent
capture reconstruction. `scripts/tcp6_audit.py` reopens retained evidence and
serialized damaged controls. The client uses `TCP_IPV6` in the existing
`userspace/tests/net/tcp_fault.c`; IPv4 keeps the same workload and deadlines.

`tcp6/profiles.py` selects loss, path-MTU or ordinary-error workloads while reusing native
namespace, TAP, process-group and boot ownership. The PMTU client is
`userspace/tests/net/tcp6/pmtu.c`; its controlled peer and independent decoder are
`scripts/tcp6/pmtu_peer.py` and `pmtu_capture.py`. Compiler dependency aliases
such as `tcp6/../ipv6_fixture.h` are matched against the canonical frozen source
inventory; paths which escape that inventory reject.

The ordinary-error client is `userspace/tests/net/tcp6/errors.c`.
`scripts/tcp6/errors_peer.py` injects errors quoting actual transmissions;
`errors_capture.py` independently reconstructs quotes, request generations,
surviving streams and monotonic observation bounds. Native malformed-version
behavior stays explicit rather than being treated as parser equivalence.

`scripts/tcp6/scoped_peer.py` selects identical link-local tuples on separate
interface zones. It reuses the original loss peer and
`userspace/tests/net/tcp_fault.c` with `TCP_IPV6_LINK_LOCAL`; the common capture
reader additionally checks actual socket scope IDs, bound ports and observed
same-zone bind denial after close. Global and
scoped workloads keep separate program names, source flags and evidence outputs.

`userspace/tests/net/ipv6_error_record.h` formats raw/UDP ICMPv6 metadata into
one bounded console write. `scripts/tests/ipv6_error_record_test.py` runs that
actual formatter against retained interrupted bytes and failed-write controls.

The established-source TCP workload is `userspace/tests/net/tcp6/source_lifetime.c`.
`scripts/tcp6/source_peer.py` coordinates actual output and address-mutation
barriers; `source_capture.py` reconstructs the complete streams independently.
The existing profile/native/guest/evidence modules retain boot, namespace,
program, source and packet ownership. `tcp6_source_policy` shares connection
source ownership across output and path-MTU lookups. Bound descriptions and pending
connections retain their validated source while every output still needs a current route.
`userspace/tests/net/tcp6/pending_source.c`, `scripts/tcp6/pending_peer.py` and
`pending_capture.py` measure pre-bound connects, active SYN and passive SYN-ACK retries
after address removal. The same runner and independent reader retain all three native
and eight guest profiles, programs, source archives, images and packet clocks.
Fresh binds and automatic source selection still require current address assignment.

`userspace/tests/net/tcp6/scoped_source.c` measures link-local source withdrawal,
same-address zone ownership and quiet device-binding name queries.
`scripts/tcp6/scoped_source_peer.py` specializes the source flow observer;
`scoped_source_capture.py` reconstructs complete streams, zone records and quiet
intervals, and reopens serialized damaged evidence. The paired reader is
`scripts/tests/tcp6_scoped_source_evidence_test.py`. Shared native/guest modules
retain all profiles, images, programs, complete sources and packet clocks.

`userspace/tests/net/tcp6/zone_route.c` measures cleared-device route selection,
fallback, restoration and rebinding with both physical links.
`scripts/tcp6/zone_route_peer.py` shares each stream across the controlled link
peers through the existing peer-binding hook. `zone_route_capture.py` reconstructs
both captures, per-link fences, raw route inventories and complete TCP streams.
`scripts/tests/tcp6_zone_route_evidence_test.py` checks both complete matrices,
matching clients, actual images and serialized packet/product/matrix controls.

`userspace/tests/net/tcp6/source_expiry.c` configures actual finite address lifetimes,
observes fresh bind retirement and owns an independent peer host route. The
`scripts/tcp6/expiry_peer.py` specialization retains the pending TCP flow observer;
`expiry_capture.py` independently reconstructs clocks, complete TCP streams and
route snapshots. It reuses the existing native/guest/source/product/image boundary
and provides serialized semantic controls for lifetime, route and transport evidence.

`userspace/tests/net/tcp6/zone_source_route.c` combines scoped source withdrawal
with device clearing and route reselection. Its peer and capture reader live in
`scripts/tcp6/zone_source_route_*.py`. The reader binds complete original native
clocks before sending an unchanged packet subset to the existing route decoder;
it checks companion traffic, actual address inventories and ownership fences
separately. Shared native/guest execution and image/product/source ownership
remain in the existing TCP6 harness.
