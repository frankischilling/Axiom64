# Feature roadmap

Axiom64 targets a modular monolith kernel in C++ and Assembly with services and applications in Ring 3. Linux x86-64 is the primary userspace ABI. This roadmap preserves the complete requested feature scope, including legacy binary formats and the application catalog.

The next implementation order is persistent storage, threads, then networking. Start with virtio block and writable ext2; add ext4 later. Provide POSIX pthreads and futexes before SMP. The first usable network release must acquire a DHCP lease, resolve DNS, exchange TCP/UDP traffic, answer ping, and download a file. Static network configuration must also work. Default DHCP configures every connected Ethernet adapter, with saved static settings taking precedence for each interface.

Accounts, permissions, and secure randomness must work before network services are exposed. Developer tools come first among new application groups. Full self-hosting is a milestone: build the kernel and packages inside Axiom64, then boot the result. Expand musl first, then glibc and ordinary Linux applications; Linux i386 is the next binary compatibility target.

Bash is the selected default interactive shell. Add a lightweight window manager next and develop X11 and Wayland as parallel tracks. Keep CDE, TDE, other window managers, and all application entries in the wider plan. Use software rendering before virtio GPU acceleration. USB input and storage precede USB audio. Start audio with QEMU HD Audio playback and recording, then broaden hardware support. Beyond QEMU, target UEFI desktop PCs with SATA/NVMe and USB.

Plan all service and reliability work: supervision, logging, time synchronization, scheduled jobs, SSH, desktop login, discovery, sessions, storage recovery, clean shutdown, isolation, permissions, randomness, diagnostics, crash dumps, tracing, and debugging. The distribution should have a live image, a simple disk installer, and an Axiom64 package manager with signed packages and dependency resolution.

## Working baseline

[Commit ba768b4](https://github.com/frankischilling/Axiom64/commit/ba768b40b8d55e1abae43b331f931bfff1bec4e2) has [successful CI evidence](https://github.com/frankischilling/Axiom64/actions/runs/37607497820) for BIOS/UEFI boot, static/dynamic musl, IPC, signals, BusyBox, Bash, zsh, native GNU C/C++ tools, Xorg drawing, a window manager, and emulated input into interactive Bash. [Current limits](architecture.md#current-limits) remain part of the compatibility contract. This evidence does not prove disk, network, thread, or complete Linux support.

The inventory date is 2026-10-07. `partial` means some behavior exists and the issue lists what remains. `planned` means the required capability has not been demonstrated. A catalog entry is not a claim that a driver or application works.

## Milestones

| ID | Milestone | Required outcome |
| --- | --- | --- |
| M1 | [Persistent storage](https://github.com/frankischilling/Axiom64/milestone/1) | Discover a virtio disk, mount writable ext2, and preserve guest files across reboots. |
| M2 | [Threads and memory](https://github.com/frankischilling/Axiom64/milestone/2) | Run POSIX threads with futexes, strengthen virtual memory, and then schedule on multiple CPUs. |
| M3 | [Usable networking](https://github.com/frankischilling/Axiom64/milestone/3) | Enforce accounts and permissions before network services; provide DHCP, DNS, TCP/UDP, ping, and file downloads. |
| M4 | [Developer system](https://github.com/frankischilling/Axiom64/milestone/4) | Expand musl compatibility, add glibc and Linux i386, run developer tools, and build the OS inside itself. |
| M5 | [Desktop and sessions](https://github.com/frankischilling/Axiom64/milestone/5) | Use Bash with a lightweight window manager; develop X11 and Wayland as parallel tracks. |
| M6 | [Devices and real PCs](https://github.com/frankischilling/Axiom64/milestone/6) | Add AHCI/NVMe, USB input/storage, HD Audio, virtio GPU, and ordinary UEFI desktop hardware. |
| M7 | [Additional binary compatibility](https://github.com/frankischilling/Axiom64/milestone/7) | Support BSD, System V, SunOS, Xenix, and ELKS programs, with explicit ABI and loader tests. |
| M8 | [Installable distribution](https://github.com/frankischilling/Axiom64/milestone/8) | Deliver a live image, simple installer, signed package manager, reproducible sources, and recovery tools. |

The first three milestones define the next core sequence. Later milestones describe complete tracks, not an instruction to defer prerequisites. Credentials and randomness precede remote services; verification and provenance apply to every milestone. Dependencies below describe interfaces that the full feature needs. Child tasks should be split so that, for example, storage PCI discovery does not wait for every secondary boot mode, and AHCI does not wait for USB storage.

## Tracked features

| ID | Feature | State | Milestone | Dependencies |
| --- | --- | --- | --- | --- |
| F01 | [Firmware, buses, and interrupt routing](https://github.com/frankischilling/Axiom64/issues/1) | partial | M1 | Across all tracks |
| F02 | [Block layer and virtio disk](https://github.com/frankischilling/Axiom64/issues/2) | partial | M1 | F01 |
| F03 | [Writable ext2 and later ext4](https://github.com/frankischilling/Axiom64/issues/3) | partial | M1 | F02 |
| F04 | [VFS, mounts, and pseudo filesystems](https://github.com/frankischilling/Axiom64/issues/4) | partial | M1 | F02 |
| F05 | [POSIX threads and futexes](https://github.com/frankischilling/Axiom64/issues/5) | partial | M2 | F04 |
| F06 | [Demand paging, copy-on-write, and swap](https://github.com/frankischilling/Axiom64/issues/6) | partial | M2 | F03, F05 |
| F07 | [SMP scheduling and kernel synchronization](https://github.com/frankischilling/Axiom64/issues/7) | planned | M2 | F01, F05, F06 |
| F08 | [Linux syscall and libc compatibility](https://github.com/frankischilling/Axiom64/issues/8) | partial | M4 | F05, F06, F13 |
| F09 | [Accounts, permissions, and process credentials](https://github.com/frankischilling/Axiom64/issues/9) | planned | M3 | F03, F04 |
| F10 | [Secure random number generation](https://github.com/frankischilling/Axiom64/issues/10) | planned | M3 | F03, F09 |
| F11 | [Ethernet devices and link management](https://github.com/frankischilling/Axiom64/issues/11) | partial | M3 | F01, F05 |
| F12 | [IPv4, IPv6, routing, and ICMP](https://github.com/frankischilling/Axiom64/issues/12) | partial | M3 | F11 |
| F13 | [TCP, UDP, and Linux socket semantics](https://github.com/frankischilling/Axiom64/issues/13) | partial | M3 | F12, F15 |
| F14 | [DHCP, DNS, and network configuration](https://github.com/frankischilling/Axiom64/issues/14) | partial | M3 | F09, F10, F13 |
| F15 | [IPC and event notification](https://github.com/frankischilling/Axiom64/issues/15) | partial | M2 | F05 |
| F16 | [Clocks, timers, and power management](https://github.com/frankischilling/Axiom64/issues/16) | partial | M6 | F01, F03, F05 |
| F17 | [AHCI, NVMe, and other storage devices](https://github.com/frankischilling/Axiom64/issues/17) | planned | M6 | F02, F03, F19 |
| F18 | [Additional filesystems and host sharing](https://github.com/frankischilling/Axiom64/issues/18) | planned | M6 | F02, F04, F13 |
| F19 | [USB controllers and devices](https://github.com/frankischilling/Axiom64/issues/19) | planned | M6 | F01, F09 |
| F20 | [Terminals, input, and framebuffer console](https://github.com/frankischilling/Axiom64/issues/20) | partial | M5 | F05, F19 |
| F21 | [X11 and Wayland display servers](https://github.com/frankischilling/Axiom64/issues/21) | partial | M5 | F05, F13, F20 |
| F22 | [Virtio GPU and accelerated graphics](https://github.com/frankischilling/Axiom64/issues/22) | planned | M6 | F01, F19, F21 |
| F23 | [Shells, window managers, and desktop environments](https://github.com/frankischilling/Axiom64/issues/23) | partial | M5 | F20, F21 |
| F24 | [HD Audio and multimedia interfaces](https://github.com/frankischilling/Axiom64/issues/24) | planned | M6 | F01, F05, F19 |
| F25 | [Init, login, and system services](https://github.com/frankischilling/Axiom64/issues/25) | partial | M3 | F09, F10, F14 |
| F26 | [Signed packages and dependency resolution](https://github.com/frankischilling/Axiom64/issues/26) | planned | M8 | F03, F09, F10, F14, F28 |
| F27 | [Live image and simple disk installer](https://github.com/frankischilling/Axiom64/issues/27) | planned | M8 | F03, F09, F16, F26 |
| F28 | [Native development and full self-hosting](https://github.com/frankischilling/Axiom64/issues/28) | partial | M4 | F03, F05, F08, F14, F34 |
| F29 | [Linux i386 compatibility](https://github.com/frankischilling/Axiom64/issues/29) | planned | M4 | F01, F08 |
| F30 | [BSD executable personalities](https://github.com/frankischilling/Axiom64/issues/31) | planned | M7 | F29, F33 |
| F31 | [System V and SunOS personalities](https://github.com/frankischilling/Axiom64/issues/32) | planned | M7 | F13, F20, F29, F33 |
| F32 | [ELKS and Xenix legacy programs](https://github.com/frankischilling/Axiom64/issues/33) | planned | M7 | F29, F31, F33 |
| F33 | [Executable formats and compatibility adapters](https://github.com/frankischilling/Axiom64/issues/34) | partial | M7 | F06 |
| F34 | [Debugging, tracing, and profiling](https://github.com/frankischilling/Axiom64/issues/35) | partial | M4 | F05, F06 |
| F35 | [Reliability and compatibility verification](https://github.com/frankischilling/Axiom64/issues/36) | partial | M8 | Across all tracks |
| F36 | [Base commands and runtime library coverage](https://github.com/frankischilling/Axiom64/issues/37) | partial | M4 | F04, F08, F23, F28 |
| F37 | [Reproducible distribution and source provenance](https://github.com/frankischilling/Axiom64/issues/38) | partial | M8 | F26, F28 |

## Implementation workflow

Use small feature branches and PRs with guest tests and documentation. Each issue is a feature area with a checklist; split its work into child issues and small PRs as implementation starts. Branch suggestions and acceptance requirements are in [the catalog](feature-catalog.json). Issue dependencies must be refined to the specific child task so that unrelated later work does not block an early milestone.

Link a PR to the exact tasks it completes. Keep an area issue open until every requirement has evidence. Report an application as bundled separately from demonstrated. Preserve the full firmware suite; add disk reboot, controlled network peer, threading, audio, and real hardware evidence when the corresponding feature is claimed. Do not substitute host operations for the guest behavior being tested.

Use the development kernel branch as the integration base until it reaches main. Keep private answers under `.local/`; do not copy the questionnaire or private inputs into commits or source bundles.

## Detailed scope

### F01. Firmware, buses, and interrupt routing

Limine BIOS/UEFI boot, legacy PIT/PIC interrupts, PCI configuration-mechanism-1 enumeration, virtio DMA, and [bounded ACPI HPET discovery](time.md) work. PCIe ECAM, general ACPI/firmware handoff, and interrupt routing remain planned. [The first storage delivery](https://github.com/frankischilling/Axiom64/issues/40) adds the PCI and MMIO support used by raw virtio disks.

Required work:

- PCI/PCIe enumeration and driver binding.
- MMIO mapping, DMA allocation, address limits, and cache attributes.
- ACPI table validation, MADT/FADT discovery, and firmware handoff.
- Local APIC, I/O APIC, interrupt overrides, MSI/MSI-X, and INTx routing.
- ISA and ISA Plug-and-Play resources and drivers for UART, LPT, and legacy disks.
- Boot arguments, modules, root-device selection, and firmware diagnostics.
- Secondary boot paths: Multiboot, direct QEMU, disk/floppy, and PXE/iPXE.

Acceptance evidence:

- Enumerate a QEMU PCI device with its BARs and demonstrate working DMA.
- Prove interrupt delivery before a driver relies on it and exercise an invalid resource range.
- Boot the supported firmware matrix with consistent device discovery and actionable failure logs.

### F02. Block layer and virtio disk

Modern and legacy virtio block devices provide persistent sector I/O, Linux block nodes, explicit flushes, and exclusive filesystem claims. Ext2 volumes have a bounded [read cache](ext2.md#write-and-error-behavior). [Storage tests](storage.md#verification) cover host disk bytes, fresh guest boots, read-only disks, queue rollover, and backend errors. [The first raw-disk delivery](https://github.com/frankischilling/Axiom64/issues/40) and [ext2 follow-up](https://github.com/frankischilling/Axiom64/issues/45) leave partitions, general block caching and writeback, and stable root identifiers for later work.

Required work:

- Common block operations with bounds, flush, and error propagation.
- Virtio PCI transport and virtio-blk request queues.
- Buffer cache with documented read/write policy.
- GPT, MBR, and BSD disk-label parsing with overflow checks.
- Device/partition nodes and stable root selection by label or identifier.
- Guest-owned disk image creation and reusable reboot harness.

Acceptance evidence:

- Write and read sectors through the guest driver and compare host disk bytes.
- Reject out-of-range and malformed partition requests.
- Flush, stop QEMU, start a second guest using the same disk, and recover the written data.

### F03. Writable ext2 and later ext4

Classic ext2 root and data volumes support persistent files, directories, direct/indirect and sparse storage, mount policy, metadata operations, host fsck, and reboot verification. [The data-volume delivery](https://github.com/frankischilling/Axiom64/issues/45), [disk-root delivery](https://github.com/frankischilling/Axiom64/issues/55), and [format/test limits](ext2.md) describe this slice. Advanced formats and recovery remain planned. Every requirement below remains in the complete filesystem area.

Required work:

- Writable ext2 inodes, directories, indirect blocks, allocation, and links.
- Mount, unmount, sync, truncation, rename, permissions, and timestamps.
- Root or data mounts on virtio block.
- Host fsck interoperability and read-only/error handling.
- Extended attributes, large files, indexed directories, and extent support.
- Later ext4 journal/recovery and explicit feature-bit negotiation.

Acceptance evidence:

- Create, grow, rename, link, unlink, and truncate files in the guest and verify them after reboot.
- Read guest-created content using host filesystem tools and pass fsck after clean shutdown.
- Exercise full-disk, unsupported-feature, and damaged-metadata cases without corrupting unrelated files.

### F04. VFS, mounts, and pseudo filesystems

RAM and classic ext2 mounts, filesystem dispatch, directory identity, read-only policy, mount-aware statfs, rename, links, pipes, and selected synthetic device metadata work. [Mount tests and limits](vfs.md) describe the mount interface from [#42](https://github.com/frankischilling/Axiom64/issues/42) and the [ext2 delivery](https://github.com/frankischilling/Axiom64/issues/45); the remaining requirements below stay open.

[Local advisory file locks](file-locks.md) add canonical inode ownership, fork/dup lifetime, retained waits and checked process teardown in [#76](https://github.com/frankischilling/Axiom64/issues/76). Record locks, anonymous descriptions, network filesystems, SMP synchronization and the full area remain required.

Required work:

- Mount graph, filesystem operations, vnode/dentry lifetime, and pathname traversal.
- File descriptions, descriptor lifetime, close-on-exec, and robust directory enumeration.
- Procfs process/system metadata and streaming files.
- Sysfs device/bus metadata, devfs, tmpfs/ramfs, and shmfs.
- Pseudo-device APIs: null, zero, full, CPUID, and privileged memory inspection.
- Chroot, mount flags, access checks, metadata, statfs, and disk usage.
- File locks, atomic rename, unlink lifetime, and concurrent lookup semantics.

Acceptance evidence:

- Mount two filesystems and verify traversal, mount boundaries, and open-handle lifetime.
- Inspect changing process and device metadata from guest tools.
- Exercise symlink loops, relative paths, chroot escapes, and simultaneous rename/unlink.

### F05. POSIX threads and futexes

Single-CPU musl pthread lifecycle, shared clone resources, TLS/FPU isolation, mutex/condition/semaphore synchronization, futex wait/wake/bitsets/requeue, and guest-compiled C++ threads are implemented. [The interface and tests](threads.md) cover worker fork/exec, group teardown, clear-TID, and shared futex backing lifetime. [Child #47](https://github.com/frankischilling/Axiom64/issues/47) tracks this slice; robust owner death, cancellation, remaining POSIX synchronization, complete signal semantics, and SMP remain planned.

Required work:

- Shared address-space lifetime and clone/clone3 thread flags.
- Thread IDs, groups, exit_group, join, TLS, and per-thread FPU state.
- Futex wait/wake with atomic expected-value checks and timeouts.
- Robust futex lists, clear-child-TID, cancellation, and process-shared synchronization.
- Pthread mutexes, condition variables, rwlocks, barriers, and semaphores.
- Thread-directed signals, masks, timers, and fork/exec interactions.

Acceptance evidence:

- Run real musl pthread create/join and TLS isolation tests.
- Stress contested locks, producer/consumer queues, timeout races, and owner death.
- Run C++ std::thread/std::mutex and prove process/thread teardown releases resources.

### F06. Demand paging, copy-on-write, and swap

User page tables and shared mappings exist; fork eagerly copies private pages.

Required work:

- VM maps, objects, pages, reservations, and bounded allocation accounting.
- Demand-paged stacks and file-backed mmap with shared page-cache coherence.
- Copy-on-write fork and page-fault permission handling.
- mremap, msync, madvise, locking, and protection edge cases.
- Page reclamation, swap, and out-of-memory behavior.
- Kernel slabs/zones, aligned pools, allocator diagnostics, and large-page opportunities.

Acceptance evidence:

- Demonstrate shared versus private file mappings and COW isolation after fork.
- Reclaim pages under pressure without losing live data.
- Exercise allocation failures, stack limits, malformed mappings, and swap recovery.

### F07. SMP scheduling and kernel synchronization

The scheduler runs one CPU with fixed process and descriptor limits.

Required work:

- Application-processor startup, per-CPU state, and interprocessor interrupts.
- Kernel threads, run queues, CPU affinity, priorities, and fairness.
- Spinlocks, mutexes, rwlocks, semaphores, condition variables, sleep queues, and turnstiles.
- Wakeup ordering, priority inheritance, lock diagnostics, and interrupt safety.
- Scalable task/descriptor accounting and process resource limits.
- Scheduler statistics, load average, and accounting.

Acceptance evidence:

- Run work simultaneously on multiple emulated CPUs and demonstrate affinity.
- Stress fork/exec/wait and shared locks with multiple CPUs.
- Detect lock misuse and verify sleeping tasks do not consume a CPU.

### F08. Linux syscall and libc compatibility

Static/dynamic musl programs and a tested syscall subset work; unsupported calls return ENOSYS.

[Local flock](file-locks.md) is compared with actual Linux for descriptor ownership, conversion, restart, stop/continue and process lifetime. Four guest boots compare both linkages on RAM/ext2. The complete syscall matrix and every requirement below remain open.

Required work:

- Machine-readable Linux x86-64 syscall/structure/flag/error matrix with tests.
- Extend musl coverage without silent successful stubs.
- glibc loader, symbol/TLS requirements, vDSO assumptions, and ordinary Linux applications.
- File/process/resource/signal/time/socket/ioctl conformance.
- Dynamic linking, dlopen/dlsym, constructors/destructors, RELRO, and shared-library unwinding.
- ELF relocation/hash/TLS matrix, canonical function addresses, and W^X library mappings.
- POSIX conformance suites and documented unsupported semantics.

Acceptance evidence:

- Tie each claimed syscall or ABI behavior to a guest test.
- Run both static and dynamic musl and glibc programs with their own loaders.
- Exercise negative/error cases and preserve older guest tests.

### F09. Accounts, permissions, and process credentials

All tasks currently use root identity without multiuser permission enforcement.

Required work:

- UID/GID, supplementary groups, real/effective/saved credentials, and umask.
- File/directory access checks, ownership, sticky bits, set-ID, and chroot.
- passwd/group/shadow storage and account-management commands.
- Login, su/sudo policy, session identity, and login records.
- Process signaling/debugging permission checks and service privilege dropping.
- Isolation/resource-limit tests before exposing network services.

Acceptance evidence:

- Create two users and prove unauthorized file access, signaling, and tracing fail.
- Start a service with a non-root identity and verify its credentials.
- Preserve accounts across reboot and test authentication failures.

### F10. Secure random number generation

Current random bytes are not a cryptographic random generator.

Required work:

- Entropy pool and a documented cryptographic generator.
- Boot seeding, persisted seed rotation, hardware-source validation, and reseeding.
- getrandom, /dev/random, /dev/urandom, blocking, and readiness semantics.
- Shared randomness for authentication, TLS, and package signature tooling.

Acceptance evidence:

- Verify readiness/blocking and error behavior before and after initialization.
- Test generator state transitions using deterministic fixtures.
- Run real TLS/key-generation clients without treating timing noise alone as proven entropy.

### F11. Ethernet devices and link management

[PCI virtio-net and QEMU 82540EM e1000](network.md) share bounded Ethernet ownership and Linux raw packet sockets. Modern/legacy transport, multiple interfaces, carrier/MTU controls, rollover, and controlled-peer tests cover this slice; wider hardware, interrupt-driven completion, and advanced networking remain planned. [Children #51](https://github.com/frankischilling/Axiom64/issues/51) and [#54](https://github.com/frankischilling/Axiom64/issues/54) track the paired adapters. The usable network release still requires the complete protocol and configuration work below.

Required work:

- Network-device interface, packet buffers, statistics, MTU, and link state.
- Virtio-net first on QEMU.
- Intel e1000/e1000e and Realtek RTL8139/RTL8168 drivers.
- DMA rings, interrupt moderation, buffer ownership, and backpressure.
- Multiple interfaces, MAC filtering, multicast, and link transitions.

Acceptance evidence:

- Exchange captured Ethernet frames between the guest and a controlled peer.
- Test receive/transmit ring wraparound, queue saturation, and link loss.
- Exercise each claimed NIC model with its own emulator or hardware evidence.

### F12. IPv4, IPv6, routing, and ICMP

The [initial IPv4 host path](ipv4.md) supports static addresses, connected and explicit routes, loopback, bounded ARP, raw ICMP sockets, and echo/ping on both Ethernet adapters. [Netlink control](netlink.md) adds bounded main-table dumps, protocol/scope-filtered route mutations, and complete address updates. Options and fragments are rejected; complete IPv4, IPv6, reassembly, multicast, and path MTU behavior remain required. [The initial implementation task](https://github.com/frankischilling/Axiom64/issues/61), [route-control prerequisite](https://github.com/frankischilling/Axiom64/issues/67), and [address/ownership task](https://github.com/frankischilling/Axiom64/issues/69) cover these slices.

Required work:

- Ethernet framing, ARP, IPv4 checksums, loopback, routing, aliases, and gateways.
- ICMP errors and echo/ping.
- Bounded fragment reassembly, malformed-packet handling, and path MTU discovery.
- IPv6 neighbor discovery, ICMPv6, addresses, routes, and router advertisements.
- Broadcast/multicast, packet options, TTL/TOS, and interface accounting.

Acceptance evidence:

- Ping loopback and a controlled host peer, with packet capture proving guest-generated traffic.
- Reassemble permitted fragments and reject corrupt lengths/checksums.
- Exercise IPv6 reachability, route changes, and path MTU behavior.

### F13. TCP, UDP, and Linux socket semantics

Unix stream sockets support X11, [AF_PACKET raw sockets](network.md) exchange Ethernet, and [AF_INET raw ICMP sockets](ipv4.md) support ping. [IPv4 UDP sockets](udp.md) add datagrams with tested checksums, binding, queues, errors, readiness, and retained I/O. [NETLINK_ROUTE sockets](netlink.md) support bounded tagged IPv4 route control, dumps, complete address updates, and retained datagram I/O. Unix datagram descriptors currently support interface configuration only. TCP, IPv6 UDP, Unix datagram data, deadlines, ancillary data, and the complete socket contract remain planned.

Required work:

- AF_INET/AF_INET6 TCP/UDP socket lifecycle, options, and errors.
- TCP sequence/window handling, retransmission, congestion, close, and reset.
- Datagram boundaries, peer addressing, connected UDP, and payload limits.
- AF_UNIX datagrams, credentials, SCM_RIGHTS, shutdown, and descriptor lifetime.
- AF_PACKET/raw sockets and netlink routing/device queries.
- sendmsg/recvmsg, batches, readiness, nonblocking I/O, and interruption.

Acceptance evidence:

- Transfer data in both directions with a real host TCP/UDP peer.
- Inject loss, duplication, reordering, truncation, and resets.
- Run guest client/server programs and verify poll/epoll, ancillary data, and error semantics.

### F14. DHCP, DNS, and network configuration

Linux interface/route ioctls and BusyBox `ifconfig`, `route`, and numeric `ping` support [static configuration](ipv4.md#configuration-and-routing). [C++ configuration/DHCP modules](network-configuration.md) add saved profiles, journaled address/route ownership, packet decoding, lease state, and dedicated real-wire acquisition/renewal/rebinding/release tests. [Resolver metadata](network-configuration.md#owned-resolver-metadata) merges bounded interface contributions and preserves manual files through checked publication/recovery. Normal manager startup, concurrent default clients, coordinated resolver updates, complete fault/reboot coverage, DNS resolution, and downloads remain required in [#66](https://github.com/frankischilling/Axiom64/issues/66) and the parent scope.

Required work:

- DHCP by default, lease renewal, saved configuration, and static override.
- DNS resolver including UDP, TCP fallback, search rules, and timeouts.
- Address, route, hostname, and interface tools.
- First release: DHCP, DNS, TCP/UDP, ping, and file download.
- HTTP/HTTPS tools with certificate validation and useful failure diagnostics.

Acceptance evidence:

- Acquire a lease from a controlled server and resolve a controlled DNS name.
- Download an exact fixture and verify its hash in the guest.
- Test DHCP loss, static configuration, DNS failure, TLS failure, and reboot behavior.

### F15. IPC and event notification

Pipes, Unix streams, polling, epoll, select, and SysV shared memory have guest tests.

Required work:

- Complete pipe/FIFO, poll/select/epoll, descriptor-generation, and close semantics.
- System V semaphores, message queues, and shared-memory permissions/lifetime.
- POSIX named/unnamed semaphores and priority message queues.
- eventfd, signalfd, timerfd, filesystem notifications, and POSIX asynchronous I/O.
- Shared-memory and socket descriptor passing between processes.
- Timeout, interruption, cancellation, and shutdown behavior.

Acceptance evidence:

- Run cross-process queue/semaphore/shared-memory tests with timeout and permission failures.
- Stress readiness across descriptor reuse, close, fork, and exec.
- Verify asynchronous notifications and cancellation using actual guest processes.

### F16. Clocks, timers, and power management

Boot-relative clocks use [checked HPET elapsed accounting or a calibrated fixed-frequency single-CPU TSC fallback](time.md). PIT scheduling and resolution remain 100 Hz/10 ms. [Child #73](https://github.com/frankischilling/Axiom64/issues/73) checks delayed storage intervals and overdue absolute futex/interval timers. RTC/calendar time, complete clock-ID semantics, higher-resolution deadlines, ACPI PM timer, SMP, and power transitions remain required.

Required work:

- RTC wall clock, monotonic/realtime clocks, and clock setting permissions.
- HPET, ACPI PM timer, calibrated TSC, and higher-resolution deadlines.
- POSIX interval timers, timer notifications, sleeping, and scheduling deadlines.
- ACPI shutdown/reboot and firmware runtime services.
- CPU idle states, later suspend/resume, and device power transitions.
- Time synchronization and timezone data integration.

Acceptance evidence:

- Measure clock behavior against a controlled host and test clock changes separately from monotonic time.
- Verify clean shutdown flushes storage and reboot restores it.
- Exercise timer cancellation, missed deadlines, and supported power transitions.

### F17. AHCI, NVMe, and other storage devices

The guest currently has no disk-controller drivers.

Required work:

- AHCI/SATA, including controller quirks and appropriate RAID-mode discovery.
- NVMe queues, namespaces, resets, and transfer limits.
- Legacy IDE PIO/DMA and ATAPI.
- Common SCSI layer, virtio-scsi, optical devices, and USB storage integration.
- Ramdisk and floppy devices where legacy tests require them.
- Hotplug, timeouts, cache flush, and failed-device recovery.

Acceptance evidence:

- Run the persistent filesystem/reboot suite on each claimed device type.
- Exercise controller reset, transfer bounds, and failed I/O.
- Compare written bytes against a host-readable disk image.

### F18. Additional filesystems and host sharing

Only RAM/initramfs filesystem content is available.

Required work:

- FAT and exFAT read/write, including allocation and entry checksums.
- UDF read/write and optical-media integration.
- Minix and System V filesystem formats.
- Virtio-9P and 9P protocol support for controlled host sharing.
- FUSE request/response interface and userspace filesystems.
- Filesystem tools, fsck/mkfs, unsupported-feature handling, and recovery.

Acceptance evidence:

- Run create/read/write/rename/delete and remount tests for each claimed writable format.
- Verify guest output with independent host tools and filesystem checkers.
- Reject corrupt structures and test failed or disconnected host-sharing servers.

### F19. USB controllers and devices

Input currently comes from PS/2; no USB stack exists.

Required work:

- xHCI, EHCI, and UHCI controllers and interrupt/completion processing.
- Enumeration, descriptors, hubs, hotplug, and device-tree reporting.
- HID report parsing, keyboards, mice, and evdev integration.
- Mass storage Bulk-Only and UAS through the common SCSI layer.
- usbfs/user access, permission policy, and lsusb-style inspection.
- USB Audio Class after keyboards, mice, and storage.

Acceptance evidence:

- Enumerate a hub with input and storage devices and use them from guest programs.
- Disconnect/reconnect during I/O without stale pointers or leaked resources.
- Test malformed descriptors, timeouts, and independent controller variants.

### F20. Terminals, input, and framebuffer console

Serial, PTYs, PS/2 events, and Xorg framebuffer input work.

Required work:

- Complete terminal discipline, termios, process groups, sessions, and job control.
- Virtual terminals, console switching, ANSI handling, and resize.
- PS/2 and USB input queues with correct event timestamps and overflow behavior.
- Keyboard layouts, modifiers, mouse buttons/wheel, and input-device discovery.
- UART console devices, console selection, VGA text, and framebuffer drawing.
- PSF/BDF/PCF font loading, font cache, and console geometry.

Acceptance evidence:

- Run shell job-control and terminal conformance tests.
- Switch virtual terminals while preserving their sessions and display contents.
- Verify keyboard/mouse input under both firmware types and disconnect supported devices safely.

### F21. X11 and Wayland display servers

Xorg fbdev, twm, xterm, and rendered pixels have BIOS/UEFI guest evidence.

Required work:

- Improve Xorg fbdev/evdev compatibility and enable its threaded paths when supported.
- Parallel Wayland compositor/client track with explicit kernel requirements.
- Software rendering, shared buffers, event delivery, and clipboard/session behavior.
- Shared-memory transport, fd passing, input permissions, and display isolation.
- Xwayland and interoperability when prerequisite interfaces are present.
- Application-visible rendering and real interactive-input tests.

Acceptance evidence:

- Run real X11 and Wayland clients and compare rendered output to expected pixels.
- Send emulated input through the guest input stack and observe application behavior.
- Verify server restart/session teardown and resource cleanup.

### F22. Virtio GPU and accelerated graphics

Display uses a fixed boot framebuffer without acceleration.

Required work:

- Virtio GPU resource/scanout/cursor operations.
- Display modes, buffer ownership, hotplug, and multihead groundwork.
- DRM/KMS-like interfaces required by selected compositor/rendering stacks.
- Mesa/software renderer integration before accelerated contexts.
- Explicit accelerated-rendering transport, feature negotiation, and isolation.
- Legacy VGA/BGA paths and fallback for ordinary UEFI PCs.

Acceptance evidence:

- Render and read back pixels using the guest graphics driver.
- Change supported modes and demonstrate compositor buffer lifetime handling.
- Test unsupported acceleration features and device resets with a working fallback.

### F23. Shells, window managers, and desktop environments

BusyBox ash, Bash, zsh, twm, xterm, and xeyes work.

Required work:

- Bash as the default interactive shell while retaining ash and zsh.
- Lightweight FVWM/Openbox-style window manager next.
- Additional window managers: ctwm and matwm2.
- CDE and TDE desktop environments in the wider roadmap.
- X11 tools, fonts, fontconfig, locale/input support, and session selection.
- GTK/Motif/Tk/SDL applications and desktop application catalog.

Acceptance evidence:

- Start Bash from normal serial and desktop sessions with job control.
- Open, move, resize, close, and restart windows in each claimed manager.
- Run a smoke scenario for every claimed desktop/application rather than treating package presence as proof.

### F24. HD Audio and multimedia interfaces

There is no audio driver or audio service.

Required work:

- QEMU Intel HD Audio playback and recording first.
- AC97, Sound Blaster 16, USB Audio Class, and a null/test backend.
- DMA ring/FIFO lifetime, interrupts, resets, and device format negotiation.
- /dev/audio and OSS /dev/dsp compatibility; required ALSA-style interfaces.
- PCM conversion, channel mixing, resampling, mixers, and latency behavior.
- Desktop audio service plus codecs, SDL, players, and recording tools.

Acceptance evidence:

- Play a known waveform and compare host-captured audio.
- Record a controlled input and verify samples in the guest.
- Stress format changes, underruns/overruns, close/reset, and concurrent clients.

### F25. Init, login, and system services

Init starts desktop/serial processes and reaps children; general services are missing.

Required work:

- Minimal init, ordered startup, service supervision, restart, and clean shutdown.
- Logging/syslog, time synchronization, cron/at/batch, and accounting.
- SSH, controlled inetd/telnet compatibility, HTTP server, and network daemons.
- DHCP/network setup, device discovery, RPC/rpcbind, and D-Bus.
- Desktop login greeter, display manager, sessions, and logout.
- Service privilege separation, configuration, dependency ordering, and persistent state.

Acceptance evidence:

- Boot and stop services in dependency order with captured logs.
- Authenticate a non-root SSH/session user only after credentials and randomness work.
- Test crashes, restart loops, failed configuration, logout, and reboot persistence.

### F26. Signed packages and dependency resolution

Build-time pinned packages are imported as data; no guest package manager exists.

Required work:

- Axiom64 package format, signed metadata/packages, and trusted key management.
- Dependency/conflict/version resolution and reproducible package recipes.
- Install, upgrade, remove, file ownership, and configuration preservation.
- Transactional failure handling, rollback/recovery, offline installation, and integrity checks.
- Mirrors/cache, source packages, license notices, and build provenance.
- Guest package builds and integration with the self-hosting milestone.

Acceptance evidence:

- Install/update/remove a signed package with dependencies inside the guest.
- Reject invalid signatures, conflicts, downgrades by policy, and incomplete downloads.
- Interrupt an update and recover a bootable consistent package database.

### F27. Live image and simple disk installer

A live ISO boots with a RAM root or an [ext2 disk root](disk-root.md). Data mounts and disk-root files can persist after clean shutdown. A disk installer remains planned.

Required work:

- Maintain a live BIOS/UEFI image.
- Simple installer with target-disk selection and a reviewable partition plan.
- GPT/MBR layouts, EFI system partition, bootloader installation, and root mount configuration.
- Initial users, hostname, timezone, and network settings.
- Reboot into the installed OS without the live medium.
- Rescue/recovery tools, logs, and safe failure behavior.

Acceptance evidence:

- Install onto a disposable empty guest disk and boot it without the ISO under BIOS and UEFI.
- Preserve a test file and user account across multiple boots.
- Reject an invalid disk/layout and demonstrate recoverable failed installation.

### F28. Native development and full self-hosting

Guest GCC/binutils/Make compile and execute C/C++ examples, including exceptions.

Required work:

- Build tools, Git, editors, Python, and the developer package catalog first.
- Native GCC/binutils/GDB and portable build tools with a coherent sysroot.
- Build Axiom64 kernel, userspace, and packages from inside Axiom64.
- Static/shared C/C++ runtime, TLS, dlopen, and exceptions across shared libraries.
- Reproducible cross/native toolchain builds, headers, libraries, and source bundles.
- Native debugger, ptrace, linker inspection tools, and failed-build diagnostics.

Acceptance evidence:

- Clone or import a source tree and build/test it using only guest processes and files.
- Build a new Axiom64 kernel/image inside the guest and boot the resulting artifact.
- Compile shared C++ libraries with TLS and cross-library exceptions and run negative compilation tests.

### F29. Linux i386 compatibility

Only ELF64 Linux x86-64 userspace runs.

Required work:

- 32-bit compatibility execution on the x86-64 kernel.
- Linux i386 syscall entry, numbers, structures, time types, and errno behavior.
- ELF32/PT_INTERP loading and separate 32-bit runtime search paths.
- 32-bit TLS, FPU, signal frames, and system-call restart.
- Mixed 32/64-bit processes, IPC translation, debugging, and filesystem access.

Acceptance evidence:

- Run static and dynamic 32-bit Linux programs with their unmodified loaders.
- Exchange files and IPC with a 64-bit guest process.
- Validate pointer/structure conversion and reject cross-bitness ELF/loader mismatches.

### F30. BSD executable personalities

There is no BSD syscall personality.

Required work:

- Separate FreeBSD, NetBSD, and OpenBSD syscall/error/flag mappings.
- ELF OSABI/interpreter recognition and personality-specific runtime roots.
- Signal frames, TLS, metadata, sysctl/kinfo, and native synchronization requests.
- Static and dynamic executables with their own runtime libraries.
- Per-target architecture/bitness matrix and documented implementation limits.

Acceptance evidence:

- Run lawful test fixtures for each claimed target with observable guest behavior.
- Exercise its own dynamic loader, signals, filesystem calls, and process lifecycle.
- Keep syscall layouts and failures isolated between personalities.

### F31. System V and SunOS personalities

There is no System V or SunOS personality.

Required work:

- System V Release 3 COFF and Release 4 ELF execution.
- Call-gate entry, ABI-specific flags/errors, signal frames, and process setup.
- Static shared libraries and vendor runtime search rules.
- STREAMS transport providers, pseudo-terminals, IPC, and X11 client transport.
- SunOS 4.x a.out executable/syscall/terminal behavior.
- BSD/System V filesystem and process metadata differences.

Acceptance evidence:

- Run shells and utilities for each claimed target against their own runtimes.
- Demonstrate STREAMS socket and X11 transport behavior.
- Validate signal/terminal frames and reject malformed COFF/a.out libraries.

### F32. ELKS and Xenix legacy programs

There is no segmented 16-bit or Xenix execution support.

Required work:

- ELKS 16-bit a.out execution, syscall tables, and process metadata.
- Xenix x.out 8086/286/386 loaders and ABI selection.
- LDT/segmented execution or an explicit emulation path for modes unavailable in long mode.
- int/call-gate entry, segment limits, signals, terminal behavior, and IPC.
- Legacy runtime trees, compiler/utilities, and mixed-format process lifetimes.

Acceptance evidence:

- Run 16-bit and 32-bit fixtures with their expected segmentation and system-call entry.
- Demonstrate invalid selectors/segment bounds fault safely.
- Run representative utilities and compile/execute a small program where toolchains are available.

### F33. Executable formats and compatibility adapters

ELF64, musl PT_INTERP, and script execution are supported.

Required work:

- ELF32/ELF64, PIE, interpreter contracts, permissions, and malformed-input validation.
- a.out, ELKS a.out, COFF, x.out, and static shared-library formats.
- Shebang execution and personality selection without global ABI state.
- Experimental PE/MZ loader research, explicitly separate from a claim of Windows compatibility.
- NTSYNC-compatible mutex/semaphore/event operations for Wine research.
- Runtime/library isolation, executable branding tools, and architecture mismatch errors.

Acceptance evidence:

- Test each claimed loader with valid, truncated, overlapping, and wrong-architecture fixtures.
- Verify a failed exec preserves the prior address space.
- Record PE/Wine research as experimental until actual guest applications pass.

### F34. Debugging, tracing, and profiling

Serial diagnostics, syscall tracing, symbols, and QEMU GDB hooks exist.

Required work:

- Kernel symbols, DWARF-aware stack traces, panic diagnostics, and crash/core dumps.
- ptrace, native GDB, process inspection, and signal-safe debugging.
- Syscall/resource accounting, diagnostics, and SysRq-style controls.
- QEMU guest sampling, folded stack profiles, and symbol resolution.
- Format-string linting, static checks, memory tracking, and allocator corruption detection.
- Repeatable failed-boot/debugging procedures and preserved diagnostic artifacts.

Acceptance evidence:

- Debug a guest program through native ptrace/GDB and inspect a deliberate crash.
- Resolve a guest profile and kernel stack trace to known source locations.
- Demonstrate lint detection and diagnostic behavior with controlled faulty fixtures.

### F35. Reliability and compatibility verification

BIOS/UEFI ABI, compiler, X11 pixel, and emulated-input tests pass at the baseline.

Required work:

- Filesystem recovery, clean shutdown, and multi-boot persistence tests.
- Isolation, credentials, secure randomness, resource limits, and failure injection.
- Packet/ELF/filesystem/USB malformed-input tests and targeted fuzzing.
- Thread/SMP stress, race tests, long-running resource/leak checks, and allocator auditing.
- Diagnostics, core dumps, tracing, and kernel debugging evidence.
- CI hardware/firmware/program matrix with exact tested commit and retained artifacts.

Acceptance evidence:

- Require evidence for each claimed capability and report untested states explicitly.
- Run cross-boot, network-peer, thread-stress, and crash-recovery scenarios inside the guest.
- Keep the established full and interactive firmware suites passing.

### F36. Base commands and runtime library coverage

BusyBox and selected imported libraries cover many commands; most individual behaviors are not yet tested.

Required work:

- Every base command and library listed in the application catalog.
- Files/text/archive tools, editors/pagers/manual pages, and shell semantics.
- Accounts/process/system/device administration and terminal tools.
- Native library API equivalents: libc/libm/pthread, resolver, editing, databases, realtime, USB, process inspection, and ELF utilities.
- Locale, Unicode, fonts, timezones, and documentation lookup.
- Games, demonstrations, BASIC/calculators, and other standalone utilities.

Acceptance evidence:

- Assign each catalog entry a guest smoke/conformance test or an explicit planned state.
- Verify behavior through the chosen standard package or implementation rather than requiring duplicate implementations.
- Distinguish an imported archive from a program demonstrated to run.

### F37. Reproducible distribution and source provenance

Build inputs, package hashes, licenses, and corresponding source bundles are pinned.

Required work:

- Kernel/build documentation under docs/ with a concise README.
- Pinned host/cross/native toolchains and package dependency graphs.
- Build profiles, reproducible disk/ISO images, and deterministic manifests.
- License/copyright retention and corresponding source/patch/recipe bundles.
- Verified downloads, offline caches, package update review, and CI artifacts.
- Windows/WSL and Linux build entry points with documented prerequisites.
- Host ABI diagnostic runner for foreign binaries, kept separate from guest compatibility evidence.

Acceptance evidence:

- Build from pinned inputs in a fresh environment and validate artifacts/checksums.
- Account for every redistributed package with its notices and corresponding sources.
- Keep private decisions and reference inputs excluded from commits and source bundles.
