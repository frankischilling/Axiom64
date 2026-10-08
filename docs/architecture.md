# Architecture

Axiom64 uses one repository and build system. The kernel is a modular monolith: memory, scheduling, files, signals, IPC, and devices execute in Ring 0 behind internal interfaces. Init, shells, compilers, Xorg, and desktop clients execute as separate Ring 3 processes.

Limine loads the ELF kernel and newc initramfs through BIOS or UEFI. It supplies a memory map, direct physical mapping, and framebuffer. The kernel installs its GDT, TSS, IDT, syscall entry, and 100 Hz PIT, selects an [elapsed counter clock](time.md), discovers block devices, and selects either the initramfs or an [ext2 disk root](disk-root.md) before executing `/sbin/init`.

| Module | Responsibility |
| --- | --- |
| `kernel/arch/x86_64/arch.cpp`, `entry.asm` | CPU tables, interrupts, syscall entry, register frames, return to Ring 3 |
| `kernel/boot/root.cpp` | Root-device selection, required boot paths, and volatile runtime mounts |
| `kernel/mm/memory.cpp` | Physical allocation, page references, user page tables, validated user copies |
| `kernel/drivers/platform/pci.cpp`, `kernel/drivers/virtio/` | PCI discovery, modern/legacy virtio transport, split-ring storage and descriptor ownership |
| `kernel/drivers/block/block.cpp` | Virtio block request policy, raw sector I/O, flush, and filesystem claims |
| `kernel/net/`, `kernel/drivers/net/` | Ethernet ownership, virtio-net/e1000 devices, interface ioctls, packet sockets, IPv4/ARP/ICMP, UDP, and netlink route/address control |
| `kernel/process/task.cpp` | Process/thread ownership, ELF loading, clone/fork/exec/exit/wait, scheduling, TLS, FPU state |
| `kernel/process/futex.cpp` | Expected-value waits, wake/bitsets, requeue, deadlines, shared backing lifetime |
| `kernel/io/io.cpp` | Retained I/O requests, captured vectors, wait completion, and interruption cleanup |
| `kernel/fs/vfs.cpp`, `ramfs.cpp` | Filesystem dispatch, mount namespace, RAM volumes, initramfs, file descriptions, pipes |
| `kernel/fs/ext2/ext2.cpp` | Classic ext2 volumes, mount validation, allocation, file/directory operations, synchronous commits |
| `kernel/abi/linux/syscall.cpp` | Linux syscall numbers, ABI structures, errors, blocking operations |
| `kernel/process/signals.cpp` | Queues, masks, actions, signal frames, return, alternate stacks, timers |
| `kernel/ipc/ipc.cpp`, `shared_memory.cpp` | Unix stream sockets, readiness, epoll, select, shared mappings, SysV segments |
| `kernel/drivers/platform/devices.cpp` | Serial terminal, PTYs, framebuffer, PS/2 events, Linux block-device file operations |
| `kernel/drivers/platform/power.cpp` | PIIX4 power off after filesystem synchronization on the tested QEMU platform |
| `userspace/init/main.c` | Desktop and serial shell startup, child reaping, console shell restart |
| `userspace/net/` | C++ configuration ownership, saved profiles, resolver metadata, and DHCP packet/state/transport modules; normal manager startup remains required |

Sources and public headers use matching subsystem folders. Desktop configuration is under `userspace/desktop/`; guest and host tests are grouped by the subsystem they exercise. [Source layout and build discovery](source-layout.md) describe the paths and conventions.

Each memory context has four-level user page tables with user, write, and execute permissions. The upper half shares supervisor mappings. Syscall buffers are validated across the full range and copied through the physical mapping. Clone can share the address space, file table, working directory/umask, and signal dispositions; fork copies private pages and retains shared page references. The scheduler uses one CPU, bounded task slots, and timer preemption; syscalls execute with interrupts masked.

The ELF loader validates ELF64 segments, loads a `PT_INTERP` musl interpreter, and supplies argv, environment, and the auxiliary vector. Failed exec preserves the old address space. Successful exec ends other group members and unshares the descriptor/disposition tables. File descriptions share offsets across fork and dup; close-on-exec belongs to descriptors. Each thread preserves FS base and FPU state. [Thread ownership and futexes](threads.md) describe exit/reaping, clear-TID, supported clone flags, and synchronization limits.

[Blocking I/O](io.md) retains the selected file description and captured vector metadata while an attempt waits. Completion updates the owner's saved frame before signal delivery. Caught signals release the attempt; an `SA_RESTART` entry selects a descriptor again. Task teardown releases saved operations before memory and file tables.

Signals use the Linux x86-64 frame layout and a userspace return trampoline. Supported behavior includes caught faults, masks, alternate stacks, restartable I/O, alarms, SIGCHLD, and stop/continue reporting. PTYs track controlling sessions and foreground process groups, translate terminal input, and deliver terminal interrupt and resize signals.

The framebuffer maps Limine's physical pixel storage into userspace. Xorg's fbdev driver uses `/dev/fb0` and platform-device metadata; evdev reads PS/2 events from `/dev/input/event0` and `event1`. Unix sockets carry X11 traffic. The desktop uses software drawing with GLX disabled. Xorg's input thread remains disabled pending dedicated coverage of that path.

## Current limits

This is a development OS with a tested compatibility surface. Unsupported syscalls return `ENOSYS`; these working programs do not imply complete Linux compatibility.

- One CPU, 64 task slots, 128 descriptors per file table. Musl pthreads and C++ threads work within [the tested slice](threads.md); SMP and complete POSIX threading remain planned.
- Root identity only. No multiuser permission enforcement, security boundary for untrusted workloads, or cryptographic random generator.
- A RAM or [classic ext2 root](disk-root.md), independent RAM mounts, raw virtio disks, and [writable ext2 data volumes](ext2.md). Partitions, advanced filesystems/recovery, and a package installation service remain planned. See [mounts](vfs.md) and [storage](storage.md) for interfaces and limits.
- Unix stream sockets, [raw Ethernet packet sockets](network.md), [raw IPv4 ICMP sockets](ipv4.md), and [IPv4 UDP sockets](udp.md) with static addresses, routes, ARP, loopback, and ping on virtio-net and QEMU e1000. [Netlink sockets](netlink.md) add bounded IPv4 route dumps, tagged route control, and complete address updates. [DHCP/configuration and resolver metadata modules](network-configuration.md) have dedicated guest checks; normal DHCP startup, DNS queries, TCP, IPv6, fragmentation/reassembly, ancillary data, and the complete socket contract remain required. Unix datagram descriptors currently serve interface configuration only.
- Eager copying on fork, bounded allocations, and no general `mremap` implementation.
- Fixed framebuffer mode. No accelerated graphics, hardware gamma control, hotplug, or virtual-console switching.
- Basic terminal discipline and job control; terminal and signal semantics continue to grow with tests.
- 10 ms timer resolution and boot-relative clocks, with HPET or fixed-frequency TSC elapsed accounting; no calibrated wall clock. See [clock selection and limits](time.md).

The harness tests the guest's own kernel paths. It does not substitute host syscalls for guest operations.
