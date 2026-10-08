# Network manager integration

Issue [#78](https://github.com/frankischilling/Axiom64/issues/78) tracks normal concurrent network configuration. The current implementation supplies its singleton ownership module; concurrent clients, coordinated installation, static address conflict handling, signal teardown, and normal startup remain in progress.

`userspace/net/manager/ownership.hpp` exposes `ax::net::Ownership`. Call `open(runtime)` before opening configuration or resolver journals. It validates the private runtime path, opens a permanent `manager.lock` file, and acquires an exclusive nonblocking open-description lock. The containing directory must belong to the effective UID with mode 0700. Its ancestors must belong to root or that UID, and writable ancestors must be sticky. The file must be regular, owned by the effective UID, mode 0600, and have one link. Symlinks, unsafe path spelling, unsupported types, and inode substitution are rejected. Newly created directories and files receive their exact modes even under restrictive umasks.

The private path policy is shared with saved profiles. Acquisition checks the opened inode against its directory entry after locking and any creation synchronization. It never truncates, renames, or unlinks the lock file, including when acquisition fails. Competing opens return `EWOULDBLOCK`/`EAGAIN`; reopening an already held object returns `EALREADY`. Descriptors are nonblocking and close-on-exec. Explicit `close()` reports errors and is idempotent; destruction performs best-effort close. Final descriptor close or process death releases ownership while preserving the inode for the next process. The class cannot be copied.

Select a runtime directory on volatile storage, such as `/run/network-manager`. The kernel mounts `/run` as RAM storage when selecting an ext2 root, so runtime ownership records do not preserve lease deadlines across reboot. Saved profiles and address hints belong on the persistent root and still require fresh lease validation. Kernel accounts and permissions remain tracked in #9; effective-UID metadata checks operate within the documented trusted writer policy.

Run the native and guest ownership checks with:

```sh
sudo make test-ownership-native
make test-ownership
```

The native program runs with GNU ASAN/UBSAN and static/dynamic musl under ordinary and root UIDs. It checks eight simultaneous contenders creating the first lock, exact private modes, stable inode and opaque contents, fork/exec descriptor lifetime, restart after SIGKILL, hard links, symlinks, unsupported types, repeated writerless-FIFO rejection, and real foreign file/directory owners under root. A linker wrapper substitutes a real inode after real flock acquisition to check rejection and release. The guest matrix runs both musl programs on RAM and disposable writable ext2 across BIOS/UEFI and modern/legacy virtio. It requires clean unmount, independent host fsck, and unchanged seed bytes. Evidence is in `build/ownership-*.log`, `build/ownership-native-results.json`, and `build/ownership-results.json`. Native-only FIFO creation and foreign-owner setup are not guest credential claims.

Linux open-description semantics follow the [flock implementation](https://github.com/torvalds/linux/blob/v6.12/fs/locks.c) and [API](https://man7.org/linux/man-pages/man2/flock.2.html). The manager's protocol requirements remain [DHCP](https://www.rfc-editor.org/rfc/rfc2131) and [IPv4 address conflict detection](https://www.rfc-editor.org/rfc/rfc5227).
