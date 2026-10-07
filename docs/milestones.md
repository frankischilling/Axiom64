# Development milestones

The target is a standalone x86-64 operating system, primarily written in C++, with its own Linux-compatible userspace ABI and syscall implementation. The required userspace includes musl programs, a native GNU toolchain, and an actual X11 environment. QEMU is the first hardware target, with both BIOS and UEFI boot. BusyBox ash and Xorg framebuffer come first; additional shells and window managers follow.

1. Boot the C++ kernel and run static and dynamic musl programs in Ring 3. Verify process memory isolation, filesystem operations, fork/exec/wait, pipes, and BusyBox shell scripts under both firmware types.
2. Run native GCC and GNU binutils inside Axiom64. Compile, assemble, link, and execute C and C++ programs using guest files and guest processes. Exercise diagnostics and failed builds as well as successful ones.
3. Provide the framebuffer, input, Unix sockets, shared memory, polling, and process facilities required by Xorg. Run a real Xorg framebuffer server and X11 clients, verify protocol exchanges and rendered pixels, and start a window manager.
4. Run interactive Bash inside a window-managed Xorg desktop. Verify visible windows and commands entered through emulated input, and start that environment from the normal image.
5. Add persistent storage through virtio block and writable ext2, with files verified across reboots. Extend disk hardware to AHCI/NVMe and plan ext4 afterward.
6. Implement POSIX pthreads and futexes, then SMP. Expand memory management, IPC, synchronization, and failure tests alongside them.
7. Provide DHCP by default with a static option, DNS, TCP/UDP, ping, and file downloads. Enforce accounts, permissions, and secure randomness before exposing network services.
8. Expand developer tools and musl compatibility, then glibc and Linux i386. Build the kernel and packages inside Axiom64 and boot the resulting system.
9. Make Bash the default interactive shell and add a lightweight window manager. Develop X11 and Wayland as parallel tracks while retaining additional window managers and desktop environments in the plan.
10. Add UEFI desktop-PC hardware support, USB keyboards/mice/storage, HD Audio playback/recording, and later virtio GPU acceleration and other devices.
11. Add BSD, System V, SunOS, Xenix, ELKS, and older executable-format compatibility with separate ABI tests.
12. Deliver a live image, simple installer, signed package manager, service supervision, and recovery tools. Require reliability and source-provenance evidence throughout the work.

The implementation includes the first four milestones and the raw virtio disk portion of milestone five. [Storage tests](storage.md#verification) check sector persistence across fresh boots; writable ext2 and persistent ordinary files remain planned. The full test requires separate compiler, desktop rendering, and keyboard-input evidence; a successful kernel boot alone does not satisfy them. [The full roadmap](feature-roadmap.md) defines the remaining feature areas, dependencies, GitHub tracking, and acceptance requirements. [The application catalog](application-roadmap.md) preserves every planned command, library, and package rather than limiting the scope to the programs already running.
