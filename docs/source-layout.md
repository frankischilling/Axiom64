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

## Formatting

The root `.clang-format` contains C++20 and C profiles. Kernel sources, headers, and host tests use the C++ profile. Userspace C sources use the C profile, and native C++ test programs use the C++ profile. Both preserve include order and use four spaces and a 100-column limit. Function bodies use multiple lines, and `SeparateDefinitionBlocks: Always` inserts a blank line between function, class, struct, and enum definitions. Keep one blank line between function prototypes too; `MaxEmptyLinesToKeep: 1` preserves that spacing. The Makefile continues to select C11 and C++20 for compilation.

On the Ubuntu build host, install the formatter and run these commands from the repository root:

```sh
sudo apt-get install -y clang-format-20
make format
make check-format
```

The targets cover project C/C++ sources and headers under `kernel/` and `userspace/`. Imported headers under `vendor/` retain their upstream formatting. Set `CLANG_FORMAT=/path/to/clang-format-20` when the executable uses another name. Clang-format 20 or newer can read the separate C profile; version 20 is used for the checked formatting. CI runs `make check-format`, and the corresponding-source bundle includes the configuration.

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
Real-interface and route/error/lifetime integration remain unfinished.
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
