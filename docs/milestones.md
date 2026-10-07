# Development milestones

The target is a standalone x86-64 operating system, primarily written in C++, with its own Linux-compatible userspace ABI and syscall implementation. The required userspace includes musl programs, a native GNU toolchain, and an actual X11 environment. QEMU is the first hardware target, with both BIOS and UEFI boot. BusyBox ash and Xorg framebuffer come first; additional shells and window managers follow.

1. Boot the C++ kernel and run static and dynamic musl programs in Ring 3. Verify process memory isolation, filesystem operations, fork/exec/wait, pipes, and BusyBox shell scripts under both firmware types.
2. Run native GCC and GNU binutils inside Axiom64. Compile, assemble, link, and execute C and C++ programs using guest files and guest processes. Exercise diagnostics and failed builds as well as successful ones.
3. Provide the framebuffer, input, Unix sockets, shared memory, polling, and process facilities required by Xorg. Run a real Xorg framebuffer server and X11 clients, verify protocol exchanges and rendered pixels, and start a window manager.
4. Run interactive Bash inside a window-managed Xorg desktop. Verify visible windows and commands entered through emulated input, and start that environment from the normal image.
5. Expand window managers, persistent storage, threading, devices, and compatibility tests. Keep current limits documented and preserve pinned build inputs and CI evidence.

The implementation includes the first four milestones. The full test requires separate compiler, desktop rendering, and keyboard-input evidence; a successful kernel boot alone does not satisfy them. Further compatibility and hardware work remains in milestone 5.
