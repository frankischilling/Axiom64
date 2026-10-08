# Advisory file locks

Linux x86-64 `flock` (syscall 73) supports shared, exclusive and unlock operations on local VFS descriptions. This supplies the file-lock prerequisite in [#76](https://github.com/frankischilling/Axiom64/issues/76) for singleton service ownership in [#66](https://github.com/frankischilling/Axiom64/issues/66). Full [VFS](vfs.md), [Linux ABI](https://github.com/frankischilling/Axiom64/issues/8), and network-manager requirements remain open.

## Ownership and operations

| Operation | Behavior |
| --- | --- |
| `LOCK_SH` | Permit several independently opened shared descriptions on one canonical node |
| `LOCK_EX` | Acquire exclusive ownership when no other description holds a lock |
| `LOCK_UN` | Release this description's lock; repeated unlock succeeds |
| `LOCK_NB` | Return `EWOULDBLOCK` on conflict; combines with the three operations above |

Locks remain advisory: other descriptions can still read, write, rename or unlink the file. Read-only opens and read-only mounts permit exclusive locks. Independent opens conflict even within one process. Duplicate and fork-inherited descriptors share one lock; any of them can change or release it. A final description close releases ownership, including process exit and close-on-exec. A retained blocking operation can keep the description alive after its visible descriptors close.

Hardlink and symlink access reaches the canonical inode. Rename preserves identity. An unlinked, still-open inode retains its lock; creating a new file under the old pathname creates separate ownership. Ext2 metadata updates preserve the in-memory lock state. Lock records are never persisted to disk.

Repeated acquisition of the same mode succeeds without another shared-owner count. Converting modes first releases the old lock. A conflicting conversion can therefore return `EWOULDBLOCK` after dropping the original shared lock. Conversion does not provide atomic upgrade or deadlock detection. These contracts follow the [Linux manual](https://man7.org/linux/man-pages/man2/flock.2.html) and are checked against actual Linux execution.

## Blocking calls and lifecycle

A blocking request uses the [retained I/O module](io.md). It captures the original `Handle` and operation, then waits through that description. Closing or replacing its descriptor with `dup2` does not redirect an uninterrupted attempt. `O_NONBLOCK` has no effect on flock; `LOCK_NB` controls nonblocking acquisition.

A caught signal releases the waiting attempt. Without `SA_RESTART`, the syscall returns `EINTR`. With `SA_RESTART`, it re-enters and looks up the current descriptor. Group stop likewise discards the old attempt and permits fresh entry after continue. Successful exec, exit_group and fatal delivery release waiting threads before their shared resources are freed. The tests compare these transitions with Linux.

`kernel/fs/file_lock.cpp` owns mode validation, canonical-node shared/exclusive state, conversion and release. `kernel/io/io.cpp` owns waiting-call retention and completion; the scheduler and signal code use that existing lifetime interface. `close_handle` releases the lock only when the final reference ends. Counts and owners live in nodes and handles, bounded by the existing 1024-description pool. Operations run in the current single-CPU syscall/scheduler model; SMP requires explicit synchronization.

## Verification and limits

```sh
make test-file-locks-native
make test-file-locks
```

The guest harness first runs the common C program on Linux using GNU ASAN/UBSAN and static/dynamic musl. All three must agree on a deterministic 4096-operation trace of independent opens, repeated modes, failed conversions, descriptor duplication, close/reopen and invalid operations. Native evidence records the Linux kernel and complete logs.

Four BIOS/UEFI modern/legacy virtio boots run both guest linkages on RAM and real ext2. Every suite checks aliases, advisory I/O, fork/exec/close-on-exec lifetime, 48 blocked close/dup2 reuse cycles, `O_NONBLOCK`, interruption/restart, stop/continue, exit_group, kill, successful exec, and eight contending processes performing 256 updates while yielding under the lock. Every guest trace must match the current native result. Guest-only tests check explicit unsupported errors. Read-only ext2 lock tests, successful unmount, independent unchanged seed-file bytes and host fsck check filesystem lifetime. Evidence is in `build/file-lock-{native-results,results}.json` and `build/file-lock-*.log`.

Descriptions without a canonical VFS node, including anonymous pipes, sockets and epoll, return `EOPNOTSUPP`. `O_PATH` descriptions return `EBADF`; complete O_PATH behavior remains outside this child. Invalid modes or extra operation bits return `EINVAL` before descriptor lookup. Deprecated mandatory-lock flags also return `EINVAL`, so this implementation does not reproduce Linux's legacy ignored-success behavior for those flags. POSIX record locks, fcntl open-description record locks, NFS/SMB semantics, FIFO fairness, deadlock detection and the complete ABI remain required work.
