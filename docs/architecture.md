# Architecture

Axiom64 uses one repository and build system. The kernel is a modular monolith: memory, scheduling, files, signals, IPC, and devices execute in Ring 0 behind internal interfaces. Init, shells, compilers, Xorg, and desktop clients execute as separate Ring 3 processes.

Limine loads the ELF kernel and newc initramfs through BIOS or UEFI. It supplies a memory map, direct physical mapping, and framebuffer. The kernel installs its GDT, TSS, IDT, syscall entry, and 100 Hz PIT, selects an [elapsed counter clock](time.md), discovers block devices, and selects either the initramfs or an [ext2 disk root](disk-root.md) before executing `/sbin/init`.

## Subsystem guides

- [Persistent storage](storage.md), [filesystems and mounts](vfs.md), [advisory file locks](file-locks.md), and [extended attributes and file capabilities](file-capabilities.md)
- [Accounts and authenticated sessions](accounts.md), [threads and futexes](threads.md), and [clocks and elapsed waits](time.md)
- [Ethernet and packet sockets](network.md), [IPv4 routing and diagnostics](ipv4.md), [IPv6 addresses and sockets](ipv6.md), [UDP sockets](udp.md), [netlink](netlink.md), and [network configuration and DHCP](network-configuration.md)

## Kernel and userspace layout

| Module | Responsibility |
| --- | --- |
| `kernel/arch/x86_64/arch.cpp`, `entry.asm` | CPU tables, interrupts, syscall entry, register frames, return to Ring 3 |
| `kernel/boot/root.cpp` | Root-device selection, required boot paths, and volatile runtime mounts |
| `kernel/mm/memory.cpp` | Physical allocation, page references, user page tables, validated user copies |
| `kernel/drivers/platform/pci.cpp`, `kernel/drivers/virtio/` | PCI and PCIe discovery, modern/legacy virtio transport, split-ring storage and descriptor ownership |
| `kernel/drivers/block/block.cpp` | Virtio block request policy, raw sector I/O, flush, and filesystem claims |
| `kernel/core/random/`, `kernel/drivers/random/` | Shared generator, initialization credit, source validation, and virtio entropy ownership |
| `kernel/firmware/`, `kernel/arch/x86_64/rtc.cpp` | ACPI table validation, interrupt topology discovery, generation ID, and boot UTC calendar sampling |
| `kernel/net/`, `kernel/drivers/net/` | Ethernet ownership, virtio-net/e1000 devices, interface ioctls, packet sockets, IPv4/ARP/ICMP, UDP, TCP state/socket/error ownership, and netlink route/address control |
| `kernel/process/task.cpp` | Process/thread ownership, ELF loading, clone/fork/exec/exit/wait, scheduling, TLS, FPU state |
| `kernel/process/futex.cpp` | Expected-value waits, wake/bitsets, requeue, deadlines, shared backing lifetime |
| `kernel/io/` | Retained I/O requests, packet transfer, wait completion, and interruption cleanup |
| `kernel/fs/file_lock.cpp` | Canonical-node advisory locks owned by open descriptions |
| `kernel/fs/vfs.cpp`, `ramfs.cpp` | Filesystem dispatch, mount namespace, RAM volumes, initramfs, file descriptions, pipes |
| `kernel/fs/ext2/` | Classic ext2 volumes, mount validation and recovery, allocation, file and directory operations |
| `kernel/abi/linux/syscall.cpp` | Linux syscall numbers, ABI structures, errors, blocking operations |
| `kernel/process/signals.cpp` | Queues, masks, actions, signal frames, return, alternate stacks, timers |
| `kernel/process/signal_wait.cpp` | Captured Linux synchronous signal waits, dequeue order, timeout and interruption |
| `kernel/ipc/ipc.cpp`, `shared_memory.cpp` | Unix stream sockets, readiness, epoll, select, shared mappings, SysV segments |
| `kernel/drivers/platform/devices.cpp` | Serial terminal, PTYs, framebuffer, PS/2 events, Linux block-device file operations |
| `kernel/drivers/platform/isa_pnp.cpp`, `legacy_io.cpp` | ISA card discovery, active resource readback, polled UART and printer drivers |
| `kernel/drivers/platform/power.cpp` | PIIX4 power off after filesystem synchronization on the tested QEMU platform |
| `userspace/init/main.c`, `console.c` | Seed/network supervision, authenticated console startup, child reaping and console recovery |
| `userspace/desktop/seat.c`, `authority.c`, `terminal.c` | Authenticated display ownership, private X11 cookies, process recovery and ordinary-user terminals |
| `userspace/services/random_seed.c` | Private persisted seed loading, rotation, and interrupted-operation recovery |
| `userspace/net/` | C++ configuration ownership, saved profiles, resolver metadata, and DHCP packet/state/transport modules; normal manager startup remains required |

Boot diagnostics report the validated ACPI MADT and FADT when firmware
supplies them. The MADT lists local APIC and x2APIC processor IDs, I/O APIC
addresses and interrupt bases, and ISA source overrides. The FADT supplies the
system control interrupt and platform flags. On the single boot CPU, the
kernel uses the MADT's ISA override to route PIT IRQ 0 through the I/O APIC.
It checks the controller input ranges and observes two acknowledged timer
interrupts before switching. If validation or delivery fails, the kernel
keeps the legacy PIC/PIT path. The `irq=pic` boot option selects that path
explicitly. Modern virtio-net can route receive and transmit completions to a
shared MSI-X vector on the boot processor. The Intel 82574L adapter uses a
single PCI MSI message. Drivers keep their polling paths.

The early console checks for a scratch-register UART at COM1 (I/O port
`0x3f8`) before enabling serial output. The kernel bounds transmit waits
and exposes `/dev/ttyS0` when the probe succeeds. With a running HPET or
calibrated TSC, it also probes the standard LPT1 port (`0x378`). A detected
printer interface appears as root-owned `/dev/lp0`. It writes raw bytes in
compatibility mode and returns `EIO` if the port fails before sending any
bytes. A failure after partial output returns the number sent.

Once the clock is running, ISA Plug and Play discovery isolates cards,
validates their serial identifiers and resource data, and reads the active
I/O assignment for compatible UARTs and standard parallel ports. The
kernel keeps a working COM1 or LPT1. If the fixed-port probe finds no
device, it can bind an unambiguous active assignment at a standard
alternate port. It probes the selected device before publishing a node.

If a class has no active device, the kernel can configure an inactive
standard UART or printer that advertises one I/O range and supports ISA
range checking. It checks for an existing decoder and verifies both
range-check patterns before activation. The new device uses polling with
its IRQ selection disabled. A failed range check or driver probe triggers
restoration of the previous configuration. A failed rollback stops
further activation. Devices that require memory, DMA, or several I/O
ranges still require firmware setup. [ISA Plug and Play specification](https://ethw.org/w/images/7/7f/PNP-ISA-v1.0a.pdf)

Legacy PCI IDE compatibility channels also support polled ATA disks. Reads,
writes, partition discovery, and persistent roots use the shared block layer.
See [storage](storage.md) for device names and supported commands.

The primary ISA floppy controller uses DMA channel 2 and polls command status.
The kernel reserves a page below 16 MiB and checks DMA completion before
copying each sector to the caller. Floppy volumes bypass the block cache so
reads can detect media changes.

PCI discovery uses the validated ACPI MCFG table for PCIe configuration
registers. Each aperture identifies a PCI segment and bus range. Its base
address refers to bus zero even when the aperture starts at another bus.
The kernel rejects overlapping entries and apertures that intersect RAM or
exceed the CPU's physical address limit. It maps configuration registers
with device cache attributes and uses legacy PCI configuration ports for
segment-zero buses without a usable ECAM mapping.

The boot-time MMIO mapper checks the CPU's physical address width and
rejects ranges that share any page with RAM or retained boot data. Device
pages use a supervisor-only, writable, non-executable uncacheable mapping.
The mapper reads the processor's page-attribute table to choose the
uncacheable type and preserves already compatible entries. It stages any
new page tables and publishes them only after checking the entire range.
A rejected range leaves the old mappings intact. [Intel system programming manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

Boot also validates the DSDT referenced by the FADT and the SSDTs listed in
the ACPI root table. SSDTs retain their firmware order for namespace loading.
After verifying APIC delivery, the kernel evaluates AML to select the
interrupt model, resolve PCI pin routes, and read interrupt resources.
Bridge-local routes take precedence. When a pin has no local route,
the kernel walks the configured PCI bridge chain and rotates the pin at
each hop. It rejects ambiguous bridge ranges. The I/O APIC uses the
firmware's polarity and trigger mode. A level-triggered line can serve
several devices. Each device clears
its own interrupt cause before the local APIC acknowledges the line. A
repeatedly unclaimed line is masked and the driver resumes polling.
On i440fx, the evaluator builds the firmware's routing packages and reads
interrupt links from PCI configuration space. For a disabled PIIX link, it
selects an available, firmware-described IRQ from `_PRS`, excluding the
system control interrupt. It stages the byte write requested by `_SRS` and
checks the resulting `_CRS` and, when present, `_STA` before programming
the chipset. The PCI driver verifies the register readback. If a write fails,
the kernel attempts to restore earlier writes and withholds the routing table.
Existing firmware settings are retained. Other chipsets still use their
firmware's current settings.

Sources and public headers use matching subsystem folders. Desktop configuration is under `userspace/desktop/`; guest and host tests are grouped by the subsystem they exercise. [Source layout and build discovery](source-layout.md) describe the paths and conventions.

Each memory context has four-level user page tables with user, write, and execute permissions. The upper half shares supervisor mappings. Syscall buffers are validated across the full range and copied through the physical mapping. Clone can share the address space, file table, working directory/umask, and signal dispositions; fork copies private pages and retains shared page references. The scheduler uses one CPU, bounded task slots, and timer preemption; syscalls execute with interrupts masked.

The ELF loader validates ELF64 segments, loads a `PT_INTERP` musl interpreter, and supplies argv, environment, and the auxiliary vector. Failed exec preserves the old address space. Successful exec ends other group members and unshares the descriptor/disposition tables. File descriptions share offsets across fork and dup; close-on-exec belongs to descriptors. Each thread preserves FS base and FPU state. [Thread ownership and futexes](threads.md) describe exit/reaping, clear-TID, supported clone flags, and synchronization limits.

[Process resource limits](resource-limits.md) belong to the process, with shared thread access, fork copies and exec retention. Descriptor, regular-file size, real-UID task, address-space, private data/heap, grow-down stack and CPU limits have focused native and guest comparisons. Memory admission and stack growth live under `kernel/mm/`; runtime accounting and resource tables live under `kernel/process/`. Exec argument capture uses the process's stack allowance. Coordinated ordinary-user tests check quota pressure, denied cross-user file/process access, unchanged limits, healthy-worker progress and reclamation. Broader Linux ABI, scalability and exposed-service requirements remain in their own feature areas.

ELF programs can start through a pathname or through `execveat` using a directory or file descriptor. `AT_EMPTY_PATH` supports unlinked files, `O_PATH` descriptors, and executable anonymous memory files. Ordinary executable inodes deny new writable opens and truncation while an address space still runs the image. `AT_EXECVE_CHECK` checks access without replacing the process. The exec argument suite compares these paths with Linux under both musl providers and both linkages.

Executable `#!` scripts use the same exec path. The kernel passes the interpreter one optional argument, the script name, and the caller's remaining arguments. The kernel bounds interpreter nesting and takes credentials from the final executable image. Descriptor scripts reopen via `/dev/fd`, including unlinked scripts and sealed memory files. `execveat` returns `ENOENT` if the script's descriptor would close on exec.

[Blocking I/O](io.md) retains the selected file description and captured vector metadata while an attempt waits. Completion updates the owner's saved frame before signal delivery. Caught signals release the attempt; an `SA_RESTART` entry selects a descriptor again. Task teardown releases saved operations before memory and file tables.

Axiom64 provides `kernel/fs/proc.cpp` behind the VFS filesystem interface. Both RAM-root and ext2-root boots mount actual process/thread metadata at `/proc`. Numeric process directories and per-process task directories expose live kernel identities, groups, state, signal masks and capabilities. `self` and `thread-self` resolve relative to the caller. Status and stat reads retain a description-owned buffer; an exited task can finish already buffered bytes, while a previously unread description reports ESRCH. Cached nodes keep PID/TID identity across task-slot reuse and retire only after descriptions and directory references end. Stat field 22 records process/thread birth in actual 100 Hz clock ticks and remains stable across exec. CPU accounting, address/TTY statistics and broader procfs fields remain incomplete. The shared boot UUID uses initialized randomness and returns EAGAIN before initialization. Complete procfs, namespaces and process diagnostics remain roadmap work.

[Advisory file locks](file-locks.md) use that retained lifetime for blocking flock calls. Independent descriptions conflict on canonical local nodes; dup/fork ownership and final-close release follow the description's references.

Signals use the Linux x86-64 frame layout and a userspace return trampoline. Supported behavior includes caught faults, masks, alternate stacks, restartable I/O, alarms, SIGCHLD, and stop/continue reporting. PTYs track controlling sessions and foreground process groups, translate terminal input, and deliver terminal interrupt and resize signals.

The framebuffer maps Limine's physical pixel storage into userspace. Xorg's fbdev driver uses `/dev/fb0` and platform-device metadata; evdev reads PS/2 events from `/dev/input/event0` and `event1`. Unix sockets carry X11 traffic. The desktop uses software drawing with GLX disabled. Xorg's input thread remains disabled pending dedicated coverage of that path.

## Current limits

This is a development OS with a tested compatibility surface. Unsupported syscalls return `ENOSYS`; these working programs do not imply complete Linux compatibility.

- One CPU, 64 task slots, 128 descriptors per file table. Musl pthreads and C++ threads work within [the tested slice](threads.md); SMP and complete POSIX threading remain planned.
- [Task credentials and permissions](credentials.md) support ordinary numeric identities, capability transitions, filesystem access and privilege-dropped exec. [Account tools](accounts.md) provide persistent databases and local authentication; authenticated graphical access and complete isolation remain unfinished. [Kernel randomness](random.md) shares a BLAKE2s/ChaCha20 generator across the Linux interfaces. Axiom64 provides validated virtio input, administration, persisted seeds and generation-change handling. See [randomness](random.md) for lifecycle and cryptographic-client acceptance.
- A RAM or [ext-family disk root](disk-root.md), independent RAM mounts, virtio disks and partitions, and [writable ext-family data volumes](ext2.md). Supported ext3 and ext4 layouts recover committed journal records on boot. See [mounts](vfs.md) and [storage](storage.md) for interfaces and limits.
- Unix stream sockets, [raw Ethernet packet sockets](network.md), [raw IPv4 ICMP sockets](ipv4.md), [IPv4 UDP sockets](udp.md) and ordinary [IPv4 TCP streams](tcp.md), with static addresses, routes, ARP, loopback and ping on virtio-net and QEMU e1000. [Netlink sockets](netlink.md) add bounded IPv4 route dumps, tagged route control and complete address updates. [DHCP/configuration and resolver metadata modules](network-configuration.md), the [normal manager](network-manager.md) and [DNS queries with TCP fallback](dns.md) have guest checks. [Quoted TCP ICMP errors](tcp-icmp-acceptance.md) validate emitted ownership and Linux hard/soft diagnostics. Bounded IPv4 fragment reassembly has host policy and wire tests. IPv6, IP options/multicast, shared PMTU policy, full ancillary data coverage and the complete socket contract remain required. Unix datagrams carry owned scalar/vector records through socketpairs and named filesystem or abstract endpoints. Sender budgets, retained binding owners and generation-checked destinations preserve queued data across waits and close/reuse. Native comparisons and local root/ordinary BIOS/UEFI runs cover routing, reconnect policy, filesystem permissions and retained sends. Datagram credentials preserve sender identity through queue waits and partial ancillary output. Local checks cover both musl providers, both linkages and BIOS/UEFI as root and UID 65534. Datagram SCM_RIGHTS retains file descriptions through sender close, peeks, truncation and copy faults; bounded graph collection releases unreachable socket cycles. Streams retain sender credentials and SCM_RIGHTS ownership across queue waits and partial reads. Their retained blocking sends, MSG_WAITALL receives and listener shutdown paths have native and guest checks. Stream bindings and receive-source names follow the [Unix stream name contract](io.md#unix-stream-names). Broader stream options and lifecycle coverage remain required.
- Eager copying on fork, bounded allocations, and [resize and relocation of private anonymous mappings](resource-limits.md#anonymous-mapping-resize).
- Fixed framebuffer mode. No accelerated graphics, hardware gamma control, hotplug, or virtual-console switching.
- Basic terminal discipline and job control; terminal and signal semantics continue to grow with tests.
- 10 ms timer resolution with HPET or fixed-frequency TSC elapsed accounting. Axiom64 samples a checked UTC RTC calendar at boot; synchronization, clock setting and complete Linux clock-ID semantics remain required. See [clock selection and limits](time.md).

The harness tests the guest's own kernel paths. It does not substitute host syscalls for guest operations.

Unix streams retain byte intervals with sender identity and optional file
descriptions. Reads stop at the applicable credential or description boundary;
peeks install independent descriptor numbers while preserving queued ownership.
Consuming the first byte transfers or discards the associated descriptions and
retains any remaining bytes. The shared queued-description collector includes
streams and not-yet-accepted connections. Local native and guest checks cover
these operations; complete stream option, interruption and shutdown acceptance
remains required.
