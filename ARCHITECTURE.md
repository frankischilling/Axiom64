# Axiom64 architecture

The kernel owns x86-64 memory management, process scheduling, an in-memory filesystem, and Linux-compatible syscall dispatch. Programs execute in Ring 3 with their own page tables. The host operating system is used to build and emulate the image; the guest runs Axiom64's kernel.

Limine loads the ELF kernel and a newc initramfs through either BIOS or UEFI. It supplies the physical memory map, a direct mapping for kernel memory access, and framebuffer information. The kernel installs its GDT, TSS, IDT, syscall entry, and a 100 Hz PIT timer before executing `/sbin/init`.

`kernel/memory.cpp` allocates physical pages and manages four-level user page tables. The upper half contains shared supervisor mappings. User pages carry user, write, and execute permissions; syscall buffer transfers validate the complete user range and copy through the physical mapping. Each fork currently copies user pages. Kernel allocations and process capacity are bounded.

`kernel/entry.asm` saves registers into a common trap frame and returns with `iretq`. Syscalls use Linux x86-64 register conventions. Interrupts and blocking syscalls let the scheduler select another runnable process. Each task has a saved FPU state, FS base, descriptors, working directory, and private address space.

`kernel/task.cpp` validates ELF64 program headers and loads executable segments, including a `PT_INTERP` musl loader. It builds the initial argv, environment, and auxiliary vector on the user stack. Failed exec leaves the old executable intact. File descriptions are shared across fork and dup; close-on-exec belongs to individual descriptors.

`kernel/vfs.cpp` imports the initramfs and provides files, directories, symlinks, serial devices, and pipes. Regular files become mutable when written. Pipe endpoints track open readers and writers, and blocking I/O waits for readiness. Files are currently held in RAM and changes disappear after shutdown.

`kernel/syscall.cpp` dispatches Linux syscall numbers and returns negative Linux error numbers. It implements the operations exercised by the musl and shell tests. Unsupported operations return `ENOSYS`; this is a growing compatibility surface, not complete Linux compatibility. Signal actions and masks are stored, but general signal delivery and threads are not implemented yet. File-backed shared mappings, networking, Unix sockets, persistent disks, and usable framebuffer devices also remain to be implemented.

The root filesystem includes musl, BusyBox, init, and static and dynamic ABI tests. `/sbin/init` selects an interactive ash shell or the boot test script using the kernel-provided environment. The tests run inside the guest, and the host harness checks markers, fault diagnostics, firmware identity, and the emulator exit status. GitHub Actions runs the same BIOS and UEFI tests.
