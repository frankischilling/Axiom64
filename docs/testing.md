# Guest tests and CI

Run the full test suite:

```sh
make test
```

The harness boots QEMU under BIOS and UEFI, checks firmware identity, requires every userspace marker, and checks the guest's explicit exit status. Fault diagnostics and failed assertions reject a run. QEMU exit code 1 represents guest success through `isa-debug-exit`.

| Test | Evidence |
| --- | --- |
| Static and dynamic musl ABI | Files, hard links and unlink lifetime, directories, isolation, fork/exec/wait, mappings, pipes, descriptors |
| Threads and futexes | Static/dynamic musl lifecycle, TLS/FPU, shared resources, mutex/condition/semaphore contention and timeouts, bitset/requeue, mapping lifetime, cross-process wake, worker fork/exec, and group teardown |
| IPC | Unix sockets, edge and one-shot epoll, batches of 256 events, select/pselect, anonymous/file/SysV shared memory |
| Signals | Masks, alternate stacks, return frames, interrupted and restarted I/O, caught faults, SIGCHLD, alarms, stop/continue |
| PTYs | Sign-extended ioctls, raw I/O, controlling-terminal lookup, foreground groups, Ctrl-C and resize signals |
| BusyBox, Bash, zsh | Real shells, substitutions, pipelines, filesystem commands, exit statuses |
| Native GNU tools | Guest compiler, assembler, linker, Make, executed C/C++ results, C++ threads and condition timeouts, standard library, exceptions, rejected-source diagnostics |
| X11 | Real Xorg, drawing/GetImage comparisons, physical framebuffer pixels, twm ownership, mapped xterm with text |
| Desktop input | QEMU PS/2 mouse and keyboard; a command typed into interactive Bash creates a file checked by the guest |
| Virtio storage | Separate 16-boot firmware/transport matrix, host disk-byte comparison, fresh-boot persistence, read-only disks, index rollover, backend read/write/flush errors |
| VFS mounts | Independent RAM volumes, hidden/restored contents, directory identity, read-only policy, cross-filesystem errors, executable loading, mappings, sockets, busy unmounts, slot reuse |
| Writable ext2 | Four disk layouts across firmware/transports, guest files and executable loading, fresh-boot reads, host file/metadata comparisons and fsck, full allocation, rejected formats, and I/O retries |

The host captures `build/desktop-bios.png` and `desktop-uefi.png` after input succeeds. Logs are `build/boot-bios.log` and `boot-uefi.log`; results are in `build/boot-results.json`.

For shorter development loops:

```sh
python3 scripts/boot_test.py --suite abi --firmware bios --timeout 60
python3 scripts/boot_test.py --suite desktop --firmware bios --timeout 120
python3 scripts/boot_test.py --suite threads --phase cond --firmware both --timeout 30
python3 scripts/boot_test.py --interactive --firmware both --timeout 180
python3 scripts/storage_test.py --firmware bios --transport modern
python3 scripts/ext2_test.py --quick --firmware bios --transport modern
```

The ABI, desktop, and condition-only profiles omit large native development packages from a separate root filesystem. The full and complete threads suites use the full root filesystem. `--trace` logs syscall entry and results; `--gdb` exposes QEMU debugging on local TCP port 1234.

GitHub Actions builds the normal ISO and runs the full firmware and threads suites, raw-storage and ext2 matrices, and normal desktop checks on Ubuntu 24.04. The `axiom64-boot` artifact contains the image, kernel, logs, results, and screenshots. A separate source artifact carries upstream archives and exact package recipes. A green run applies to its tested commit; check that commit when comparing results with local changes.

Run `make test-storage` for the complete disk matrix. The harness creates and overwrites only its generated fixtures under `build/`. [Storage verification](storage.md#verification) describes the phases, host comparisons, evidence files, and paths that are not yet fault-injected.

Run `make test-ext2` for the complete filesystem matrix. [Ext2 verification](ext2.md#verification) describes supported layouts, host `debugfs`/`e2fsck` checks, failure injection, and remaining limits. The harness creates its own disk images under `build/` and accepts no user disk path.

Run `make test-threads` for the dedicated static/dynamic musl, futex, lifecycle, and guest-compiled C++ suite. [Thread verification](threads.md#verification) describes coverage and evidence files; complete POSIX threading and SMP remain planned.
