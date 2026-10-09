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
| Blocking I/O | Static/dynamic retained descriptions across close/dup2/reuse, captured vectors, socket transfers/accept, nested/restarted/abandoned signal contexts, errors, failed/successful exec, and endpoint/resource cleanup |
| IPC | Unix sockets, edge and one-shot epoll, batches of 256 events, select/pselect, anonymous/file/SysV shared memory |
| Signals | Masks, alternate stacks, return frames, interrupted and restarted I/O, caught faults, SIGCHLD, alarms, stop/continue |
| Elapsed clocks | Sanitized counter arithmetic/ACPI parsing, 24 firmware/transport/HPET-TSC/delay boots, independently timed flushes, and absolute futex/interval-timer deadlines across storage |
| Advisory file locks | GNU sanitizer and static/dynamic musl native comparisons, four guest RAM/ext2 boots, deterministic traces, retained waits, lifecycle, contention, read-only mounts and host fsck |
| PTYs | Sign-extended ioctls, raw I/O, controlling-terminal lookup, foreground groups, Ctrl-C and resize signals |
| BusyBox, Bash, zsh | Real shells, substitutions, pipelines, filesystem commands, exit statuses |
| Native GNU tools | Guest compiler, assembler, linker, Make, executed C/C++ results, C++ threads and condition timeouts, standard library, exceptions, rejected-source diagnostics |
| X11 | Real Xorg, drawing/GetImage comparisons, physical framebuffer pixels, twm ownership, mapped xterm with text |
| Desktop input | QEMU PS/2 mouse and keyboard; a command typed into interactive Bash creates a file checked by the guest |
| Virtio storage | Separate 16-boot firmware/transport matrix, host disk-byte comparison, fresh-boot persistence, read-only disks, index rollover, backend read/write/flush errors |
| Shared virtio queues | Sanitizer host simulation, concurrent chains and malformed completions; separate 24-boot real queue-size/feature matrix with host byte checks |
| Ethernet and packet sockets | 46 boots covering both NICs, firmware/transports, queue sizes, eight interfaces, rollover, link transitions, optional features, malformed completions, TX backpressure, raw socket behavior, and host byte comparisons |
| IPv4, ARP, and raw ICMP | Eight mixed-NIC boots covering firmware/transports, loopback, static configuration/routes, cache expiry/replacement, malformed input, link loss, bounded queues, retained descriptions, kernel echo/errors, BusyBox ping, and isolated device failure |
| IPv4 UDP | Eight mixed-NIC boots covering firmware/transports, native Linux comparisons, datagram boundaries, checksums and malformed input, client/server traffic, reuse and broadcast, queue pressure, retained I/O, signals, fork, link changes, and isolated device failure |
| IPv4 netlink routes | Four mixed-NIC boots, native Linux namespace comparison, sanitized message fixtures/mutations, tagged ownership and unrelated-route preservation, actual routed packets, descriptor lifetime, malformed requests, and route/socket/reply quotas |
| IPv4 address/configuration | Four mixed-NIC boots, native address-message comparison, sanitized parser fixtures/mutations, complete tuples, owned replacement/recovery, manual preservation, malformed journals, publication failure, six partial intents, and actual route-quota rollback |
| DHCP modules | Twelve codec/state/profile boots plus four independently checked real-wire acquisition/renewal/rebinding/release boots |
| Network manager | 104 actual-process boots with both NICs and musl linkages across firmware/transports: independent DHCP, saved overrides, static conflicts, manual preservation, singleton rejection, killed-process restart, and publication/teardown failure recovery |
| Private saved network files | Native GNU sanitizer and static/dynamic musl under ordinary/root UIDs, real foreign owners, writerless FIFOs and atomic publication failures; eight static/dynamic guest RAM/ext2 boots with ABI checks, unmount, seed preservation and host fsck |
| Resolver metadata | Native sanitizer checks and four guest boots for bounded eight-interface merging, complete search names, manual preservation, permissions, ownership/intent recovery, checked publication failures, and resource retry |
| VFS mounts | Independent RAM volumes, hidden/restored contents, directory identity, read-only policy, cross-filesystem errors, executable loading, mappings, sockets, busy unmounts, slot reuse |
| Writable ext2 | Four disk layouts across firmware/transports, guest files and executable loading, fresh-boot reads, host file/metadata comparisons and fsck, full allocation, rejected formats, and I/O retries |
| Ext2 root | Root and data-volume reboot persistence, software/hardware read-only policy, rejected configuration/boot files/backend failures, full userspace and normal desktop startup across firmware/transports, reproducible fixtures and host fsck |

The host captures `build/desktop-bios.png` and `desktop-uefi.png` after input succeeds. Logs are `build/boot-bios.log` and `boot-uefi.log`; results are in `build/boot-results.json`.

For shorter development loops:

```sh
python3 scripts/boot_test.py --suite abi --firmware bios --timeout 60
python3 scripts/boot_test.py --suite desktop --firmware bios --timeout 120
python3 scripts/boot_test.py --suite threads --phase cond --firmware both --timeout 30
make test-thread-io
python3 scripts/boot_test.py --interactive --firmware both --timeout 180
python3 scripts/storage_test.py --firmware bios --transport modern
make test-virtqueue
python3 scripts/virtio_test.py --firmware bios --transport modern
python3 scripts/ext2_test.py --quick --firmware bios --transport modern
python3 scripts/network_test.py --firmware bios --models virtio e1000
python3 scripts/ipv4_test.py --firmware bios --transport modern
python3 scripts/udp_test.py --firmware bios --transport modern
python3 scripts/netlink_test.py --firmware bios --transport modern
python3 scripts/configuration_test.py --firmware bios --transport modern
python3 scripts/dhcp_modules_test.py --suite state --firmware bios --transport modern
python3 scripts/profile_test.py --volume ext2 --firmware bios --transport modern
python3 scripts/dhcp_transport_test.py --firmware bios --transport modern
```

The ABI, desktop, condition-only, and I/O-only profiles omit large native development packages from a separate root filesystem. The full and complete threads suites use the full root filesystem. `--trace` logs syscall entry and results; `--gdb` exposes QEMU debugging on local TCP port 1234.

GitHub Actions builds the normal ISO, both userspace profiles, and manager test binaries once, then runs 29 isolated jobs on Ubuntu 24.04. Six cover boot/threads/queue geometry/desktop; Ethernet/IPv4/UDP/netlink; configuration/DHCP/resolver/clocks/file locks; raw storage/ext2; root/data persistence and delayed I/O; and full userspace/desktop from ext2 root. Four manager jobs each run both musl linkages for one BIOS/UEFI modern/legacy combination. One job checks randomness and saved manager hints, and two check normal init supervision by firmware. Sixteen protocol jobs each select one musl linkage, firmware, virtio transport, and affected adapter. Together they run all 272 protocol cases, including the original lease timers and packet checks. All firmware, transport, sanitizer, native Linux comparisons, host fsck, and [disk-root checks](disk-root.md#verification) remain required. Each job runs its harnesses sequentially because they share generated image paths and local debugger ports. The final `qemu` check fails if the build or any test job fails, is cancelled, or is skipped.

Runs start for pull requests, pushes to `main`, tags, and manual dispatch. Updating the same pull request or ref cancels its previous run. Feature branches get their automatic checks through a pull request, avoiding duplicate push and pull-request runs. Dependency and source archives are cached by the three lock files; the fetchers still verify their recorded hashes. Compiled outputs are shared only within the current run, with source timestamps and executable modes preserved together in a temporary archive. The build job also retains the Ubuntu packages downloaded for the common tools, their SHA-256 hashes, and installed versions. Test jobs verify those hashes and install the shared packages without downloading them again. If local installation needs updated repository metadata or extra runner dependencies, the installer refreshes metadata and installs the explicit Ubuntu package list. It seeds APT's archive cache with the verified bundle so this fallback only downloads packages absent from it.

Tool installation uses explicit packages without optional recommendations. Only the build job installs clang-format and checks formatting; test jobs reuse the checked sources without downloading the formatter and its LLVM libraries. QEMU runs headless and desktop screenshots come from QMP. The `axiom64-boot` artifact contains the normal image, kernel, and build log. The 29 `axiom64-evidence-*` artifacts contain each job's logs, results, traces, screenshots, and host dumps, including evidence from failed tests. Protocol artifact names include `-static` or `-dynamic` so each linkage retains its own reports. `axiom64-disk-root` contains the full root image and boot copies. `axiom64-sources` carries upstream archives and exact package recipes. `axiom64-ci-inputs` is the internal build archive and expires after one day. A green run applies to its tested commit; check that commit when comparing results with local changes.

Run `make test-storage` for the complete disk matrix. The harness creates and overwrites only its generated fixtures under `build/`. [Storage verification](storage.md#verification) describes the phases, host comparisons, evidence files, and paths that are not yet fault-injected.

Run `make test-ext2` for the complete filesystem matrix. [Ext2 verification](ext2.md#verification) describes supported layouts, host `debugfs`/`e2fsck` checks, failure injection, and remaining limits. The harness creates its own disk images under `build/` and accepts no user disk path.

Run `make test-threads` for the dedicated static/dynamic musl, futex, lifecycle, and guest-compiled C++ suite. [Thread verification](threads.md#verification) describes coverage and evidence files; complete POSIX threading and SMP remain planned.

Run `make test-thread-io` for the focused [blocking I/O suite](io.md#verification-and-limits). The full and complete thread suites also require its static/dynamic tests.

Run `make test-virtqueue` and `make test-virtio` for the [shared virtio queue and transport checks](virtio.md#verification). The host simulation exercises production queue logic with sanitizers; actual guest runs cover register access, negotiated geometry, disk payloads, and persistence.

Run `make test-disk-root` for the [root and data-volume persistence/rejection matrix](disk-root.md#verification). Full and normal desktop boot tests accept `--disk-root --transport modern` or `legacy`; they build a matching root fixture, copy it for each firmware boot, require the selected ext2 root, perform clean shutdown, and run host fsck.

Run `make test-network` for the complete [Ethernet and packet-socket matrix](network.md#verification). Each NIC communicates with its own loopback peer; fault and backpressure cases use a local GDB session. Results accumulate in `build/network-results.json`, and CI retains logs and debugger commands.

Run `make test-ipv4` for the [initial IPv4 and raw ICMP matrix](ipv4.md#verification). It uses both adapters together, controlled Ethernet peers, QMP link changes, and GDB cache/backpressure/device-fault probes. Results accumulate in `build/ipv4-results.json`; CI retains the logs and debugger commands.

Run `make test-udp` for the [IPv4 UDP matrix](udp.md#verification). Independent Ethernet peers inspect checksums, ports, lengths, and exact bytes; the guest exercises client/server and socket lifetime behavior. Results accumulate in `build/udp-results.json`; CI retains logs and fault-injection commands. TCP, DHCP, DNS, downloads, and the complete networking release remain required.

Run `make test-netlink-codec` and `make test-netlink` for the [route-control checks](netlink.md#verification). Build `build/netlink-native` and run `sudo python3 scripts/netlink_native.py` for the common Linux comparison in an isolated network namespace. Guest/native logs and results use `build/netlink-*`; the native comparison records its kernel version.

Run `make test-address-codec` and `make test-configuration` for the [complete address and ownership/recovery checks](network-configuration.md#verification-and-remaining-integration). Build `build/configuration-native` and run `sudo python3 scripts/configuration_native.py` for common Linux address messages in a private network namespace. Native checks exclude Axiom64-specific journal recovery and quotas. Guest/native evidence uses `build/configuration-*`.

Run `make test-dhcp-codec` for host codec/state/profile sanitizers, `make test-dhcp-modules` for their 12 guest cases, and `make test-dhcp-transport` for four real-wire cases. Evidence uses `build/dhcp-*`; the [configuration documentation](network-configuration.md) describes exact counts and remaining normal-service/reboot/fault coverage. These module fixtures do not run the normal startup daemon.

Run `make test-static-address` and `make test-manager` for the [manager composition checks](network-manager.md). Use `python3 scripts/manager_test.py --firmware bios --transport modern` for one CI cell. Reports retain each peer's counters even when verification fails; actual child status and independent address/route/file observations must agree with wire checks. `python3 scripts/manager_peer_test.py` replays complete client packets across successive leases, checks release against the latest ACK server, and rejects the prior server. `python3 scripts/manager_reboot_test.py` runs eight fresh ext2-root boot pairs, checks saved profile/hint metadata independently on the host, and requires new INIT-REBOOT transactions and ACK-derived configuration on both Ethernet adapters. Complete protocol-loss, carrier/device-fault, and normal-init supervision proofs remain required by #78.

Run `make test-random-native` and `make test-random` for [kernel randomness](random.md). Native ASAN/UBSAN covers cryptographic vectors and pool/generator/source transitions. Twenty actual guest kernels check both musl linkages, BIOS/UEFI, trusted RDSEED, CPU entropy absent, RDRAND alone, disabled CPU trust, initialized output, explicit early output, nonblocking errors, initialization waits/signals/restarts, musl retry, device polling, and user-copy failures. Initialized cells repeat as independent kernels and reject repeated samples. Logs/results use `build/random-*`; complete seed lifecycle and real TLS/key-generation clients remain required in #10.

Run `make test-resolver-native` for native Linux file/ownership contracts with sanitizers and `make test-resolver` for four guest cases. Logs/results use `build/resolver-*`, including the native kernel version. The [resolver metadata contract](network-configuration.md#owned-resolver-metadata) describes output bounds, permissions, manual ownership, and the controlled publication failures. These tests publish metadata in isolated directories; working DNS queries and normal manager integration remain required.

Run `make test-clock-codec` and `make test-clock` for [counter clocks and elapsed-wait checks](time.md#verification). Native sanitizers check scaling and bounded ACPI parsing; 24 guest cases independently time storage flushes across firmware, transports, normal HPET, absent/unsupported HPET fallback, and zero/three-second delay. Delayed cases require absolute futex and interval-timer expiry. Results and traces use `build/clock-*`; the ordinary full OS/thread/storage suites remain required.

Run `make test-file-locks` for the [advisory lock contract](file-locks.md#verification-and-limits). The harness compares three native Linux programs and sixteen guest suites across BIOS/UEFI, modern/legacy virtio, RAM/ext2 and static/dynamic musl. Traces must agree, retained descriptor/signal/teardown cases must pass, and the real ext2 seed file and host fsck are checked. `make test-file-locks-native` runs only the native comparisons. Logs/results use `build/file-lock-*`.

Run `sudo make test-ownership-native` and `make test-ownership` for [network manager singleton ownership](network-manager.md). Six native cases and eight guest boots exercise real process contention, fork/exec, process death, private path metadata, permanent inode lifetime, and inode substitution. Guest ext2 cases require checked unmount, host fsck, and preserved seed bytes. Logs/results use `build/ownership-*`; normal concurrent manager startup remains tracked in #78.
