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
| `kernel/fs/` | VFS, RAM filesystems, procfs process identity, xattrs and advisory file locks; ext2 storage and EA codec have their own subfolder |
| `kernel/security/` | Task credential transitions and bounded file capability decoding |
| `kernel/io/` | Retained blocking I/O requests |
| `kernel/ipc/` | Sockets, event counters, readiness, shared memory |
| `kernel/net/` | Ethernet interfaces, interface/route ioctls, and Linux raw packet sockets |
| `kernel/net/ipv4/` | IPv4 routes/output, bounded reassembly, shared path-MTU limits and fragment emission, ARP cache/timers, ICMP, and Internet socket descriptions |
| `kernel/net/ipv6/` | IPv6 wire validation, scoped address/route ownership, DAD, neighbor state and Ethernet host output; sockets and automatic configuration remain unfinished |
| `kernel/net/udp/` | UDP lengths, pseudo-header checksums, payload delivery, and transmission |
| `kernel/net/tcp/` | TCP wire/state/sender policy, socket ownership, timers, ISNs, TIME_WAIT and quoted ICMP errors |
| `kernel/net/netlink/` | Link/address inventories, route/address message validation, owned replies, and control socket lifecycle |
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

The corresponding-source bundle walks kernel and userspace folders recursively, so it includes the same sources and headers used by the build. [Testing](testing.md) describes the existing guest and host suites; [architecture](architecture.md) describes interfaces and current limits.

## Formatting

The root `.clang-format` contains C++20 and C profiles. Kernel sources, headers, and host tests use the C++ profile. Userspace C sources use the C profile, and native C++ test programs use the C++ profile. Both preserve include order and use four spaces and a 100-column limit. Function bodies use multiple lines, and `SeparateDefinitionBlocks: Always` inserts a blank line between function, class, struct, and enum definitions. Keep one blank line between function prototypes too; `MaxEmptyLinesToKeep: 1` preserves that spacing. The Makefile continues to select C11 and C++20 for compilation.

On the Ubuntu build host, install the formatter and run these commands from the repository root:

```sh
sudo apt-get install -y clang-format-20
make format
make check-format
```

The targets cover project C/C++ sources and headers under `kernel/` and `userspace/`. Imported headers under `vendor/` retain their upstream formatting. Set `CLANG_FORMAT=/path/to/clang-format-20` when the executable uses another name. Clang-format 20 or newer can read the separate C profile; version 20 is used for the checked formatting. CI runs `make check-format`, and the corresponding-source bundle includes the configuration.
