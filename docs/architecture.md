# Architecture

Axiom64 uses one repository and build system. The kernel is a modular monolith: memory, scheduling, files, signals, IPC, and devices execute in Ring 0 behind internal interfaces. Init, shells, compilers, Xorg, and desktop clients execute as separate Ring 3 processes.

Limine loads the ELF kernel and newc initramfs through BIOS or UEFI. It supplies a memory map, direct physical mapping, and framebuffer. The kernel installs its GDT, TSS, IDT, syscall entry, and 100 Hz PIT before executing `/sbin/init`.

| Module | Responsibility |
| --- | --- |
| `kernel/arch.cpp`, `entry.asm` | CPU tables, interrupts, syscall entry, register frames, return to Ring 3 |
| `kernel/memory.cpp` | Physical allocation, page references, user page tables, validated user copies |
| `kernel/pci.cpp`, `block.cpp` | PCI discovery, modern/legacy virtio block queues, raw sector I/O and flush |
| `kernel/task.cpp` | ELF loading, fork/exec/exit/wait, scheduling, descriptors, TLS, FPU state |
| `kernel/vfs.cpp`, `ramfs.cpp` | Filesystem dispatch, mount namespace, RAM volumes, initramfs, file descriptions, pipes |
| `kernel/syscall.cpp` | Linux syscall numbers, ABI structures, errors, blocking operations |
| `kernel/signals.cpp` | Queues, masks, actions, signal frames, return, alternate stacks, timers |
| `kernel/ipc.cpp`, `shared_memory.cpp` | Unix stream sockets, readiness, epoll, select, shared mappings, SysV segments |
| `kernel/devices.cpp` | Serial terminal, PTYs, framebuffer, PS/2 events, Linux block-device file operations |
| `userspace/init.c` | Desktop and serial shell startup, child reaping, console shell restart |

Each process has four-level user page tables with user, write, and execute permissions. The upper half shares supervisor mappings. Syscall buffers are validated across the full range and copied through the physical mapping. Fork copies private pages and retains shared page references. The scheduler uses one CPU, bounded task slots, and timer preemption; syscalls execute with interrupts masked.

The ELF loader validates ELF64 segments, loads a `PT_INTERP` musl interpreter, and supplies argv, environment, and the auxiliary vector. Failed exec preserves the old address space. File descriptions share offsets across fork and dup; close-on-exec belongs to descriptors. Each task preserves FS base and FPU state.

Signals use the Linux x86-64 frame layout and a userspace return trampoline. Supported behavior includes caught faults, masks, alternate stacks, restartable I/O, alarms, SIGCHLD, and stop/continue reporting. PTYs track controlling sessions and foreground process groups, translate terminal input, and deliver terminal interrupt and resize signals.

The framebuffer maps Limine's physical pixel storage into userspace. Xorg's fbdev driver uses `/dev/fb0` and platform-device metadata; evdev reads PS/2 events from `/dev/input/event0` and `event1`. Unix sockets carry X11 traffic. The desktop uses software drawing with GLX disabled and Xorg's input thread disabled because guest threads are not implemented.

## Current limits

This is a development OS with a tested compatibility surface. Unsupported syscalls return `ENOSYS`; these working programs do not imply complete Linux compatibility.

- One CPU, 64 task slots, 128 descriptors per task. No userspace threads or SMP.
- Root identity only. No multiuser permission enforcement, security boundary for untrusted workloads, or cryptographic random generator.
- A RAM root, independent RAM mounts, and persistent raw virtio disks. Disk filesystems, a network stack, and a package installation service remain planned. See [mounts](vfs.md) and [storage](storage.md) for interfaces and limits.
- Unix stream sockets without descriptor passing. No TCP/UDP, datagram sockets, or complete socket option support.
- Eager copying on fork, bounded allocations, and no general `mremap` implementation.
- Fixed framebuffer mode. No accelerated graphics, hardware gamma control, hotplug, or virtual-console switching.
- Basic terminal discipline and job control; terminal and signal semantics continue to grow with tests.
- 10 ms timer resolution and boot-relative clocks; no calibrated wall clock.

The harness tests the guest's own kernel paths. It does not substitute host syscalls for guest operations.
