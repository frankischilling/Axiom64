# Linux credentials and permission enforcement

Tasks carry real, effective, saved and filesystem UID/GID values, supplementary groups and Linux capability masks. Init starts with UID/GID zero and the initial capability set. Applications can create ordinary identities and drop privileges; [persistent accounts and authenticated login (#115)](https://github.com/frankischilling/Axiom64/issues/115) are separate work under [#9](https://github.com/frankischilling/Axiom64/issues/9) and [#25](https://github.com/frankischilling/Axiom64/issues/25).

## Ownership and task transitions

The production policy lives in `kernel/security/credentials.cpp`, with a narrow interface in `kernel/include/security/credentials.hpp`. Linux syscall adaptation lives in `kernel/abi/linux/credentials.cpp`. VFS, process, IPC and network code call this policy instead of inferring privilege from a zero UID.

Each task owns its identity and capability values. Supplementary groups are immutable sorted lists retained across clone/fork and released during task teardown. Changes validate and allocate a replacement before installation. A failed allocation, invalid group or user-copy fault preserves the previous list. Lists accept up to 65,536 entries and retain duplicates as Linux does. A temporary credential copy used for same-task validation or exec borrows the group list; `credential_inherit` creates a retained owner for another task.

Raw Linux identity syscalls change the calling task. Static and dynamic musl's pthread wrappers synchronize their changes across the thread group. Clones inherit the caller's credentials even when other resources are shared. The current scheduler serializes these operations on one CPU; the reference counts and credential installation need an SMP synchronization audit before the [multi-CPU feature](https://github.com/frankischilling/Axiom64/issues/7) can be accepted.

Supported calls include UID/GID queries, `getresuid/getresgid`, `setuid/setgid`, `setreuid/setregid`, `setresuid/setresgid`, `setfsuid/setfsgid` and supplementary-group queries/changes. IDs are unsigned 32-bit values. The all-ones value means unchanged only for APIs that define that convention. Filesystem-ID changes return the old value, including denied requests. Saved identities permit a temporary drop; replacing all root identities without retained capabilities prevents regaining root.

## Capability and exec policy

`capget/capset` accept the Linux v1/v2/v3 structures and expose permitted, effective and inheritable sets. The model stores capability numbers 0 through 40, plus bounding and ambient sets. `prctl` supports keep-caps, securebits and their locks, bounding-set read/drop, ambient operations, no-new-privileges and dumpability. Setting no-new-privileges is irreversible and persists through clone and exec. Capability changes cannot increase the permitted set, effective bits must be permitted, and ambient bits remain both permitted and inheritable.

The kernel enforces the following capability checks at implemented interfaces:

| Interface | Required privilege |
| --- | --- |
| Arbitrary UID/GID or group changes | `CAP_SETUID` / `CAP_SETGID` |
| DAC bypass, ownership and set-ID retention | `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_FSETID` as applicable |
| Signals across unrelated identities | `CAP_KILL` |
| Tracing permission override | `CAP_SYS_PTRACE`; tracing operations themselves remain unimplemented |
| Packet/raw IPv4 sockets, reserved UDP ports | `CAP_NET_RAW` / `CAP_NET_BIND_SERVICE` |
| Address/route/link mutation through ioctl or route netlink | `CAP_NET_ADMIN` |
| System V shared-memory permission override/control | `CAP_IPC_OWNER` / `CAP_SYS_ADMIN` |
| Mount/remount/unmount, chroot, reboot | `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, `CAP_SYS_BOOT` respectively |

ELF exec checks directory search, regular-file type, executable mode and `noexec` for both the program and its interpreter. An interpreter can be executable without being readable by the caller. Set-UID and executable set-GID mode bits produce candidate credentials; `nosuid` and no-new-privileges suppress those changes. Exec computes saved/filesystem IDs, capability sets and the UID/GID/secure auxiliary values. It commits credentials only after the replacement image and task resources succeed. Failed exec preserves the caller's credentials.

Ordinary exec preserves valid ambient capabilities. A privilege-changing set-ID exec clears them; root compatibility uses the bounding and inheritable sets. Keep-caps is cleared at exec. Identity or filesystem-identity changes, and acquisition of permitted capabilities, reset the shared memory context's dumpability. Privileged exec supplies `AT_SECURE` and disables dumpability.

This is the task capability model. [File capability xattrs (#116)](https://github.com/frankischilling/Axiom64/issues/116), user namespaces, security modules, ACLs, auditing, seccomp and a complete tracing engine are not implemented. Stored capability bits do not establish support for an absent syscall or subsystem. These gaps remain required work for [F09](https://github.com/frankischilling/Axiom64/issues/9), [F04](https://github.com/frankischilling/Axiom64/issues/4) and [F34](https://github.com/frankischilling/Axiom64/issues/35).

## Filesystem access and retained resources

VFS checks directory search at each traversed component. Open uses filesystem identities and supplementary groups; `access` uses real identities, while effective-access requests use filesystem credentials. Creation checks the parent, applies the umask and inherits a set-GID parent's group. New files on RAM and ext2 record filesystem UID/GID. Ext2 stores the low and high owner fields, preserving full-width IDs across host inspection and reboot.

Owner/group/other mode checks apply to file access and execution. Changing mode requires ownership or `CAP_FOWNER`; ownership changes require `CAP_CHOWN`, except permitted owner-to-member-group changes. Sticky directories restrict unlink and rename. Protected hardlink and sticky-directory symlink rules prevent linking or following another owner's privileged files through writable shared directories. Ordinary file writes and truncation remove privilege-bearing set-ID bits when the caller lacks `CAP_FSETID`.

Mounts retain read-only, `nosuid`, `nodev` and `noexec` policy. Read-only mounts reject mutation, `nodev` rejects opening device nodes, and `noexec` rejects exec and executable file mappings. A file mapping created on a noexec mount cannot later gain execution through `mprotect`, including after fork. Open-file access rights survive a later credential drop; they do not acquire additional rights from the current identity. Shared mappings opened without write rights retain that bound.

Chroot changes the task's filesystem root without changing its current directory or closing descriptors. Absolute paths and absolute symlink targets begin at that root; `..` stops at it when traversing from inside. Relative symlinks preserve their containing directory. Retained descriptors, including directory descriptors outside the new root, remain usable under Linux semantics. Chroot alone therefore does not provide session isolation. Filesystem context sharing follows `CLONE_FS`.

Signals check real/effective sender identities against real/saved target identities, with the same-session `SIGCONT` exception and same-thread-group behavior. Delivered `siginfo` records the sender's real UID. Process-group changes apply Linux parent/session/exec restrictions. Ptrace denies disallowed identity, dumpability and capability combinations before returning `ENOSYS` for the remaining unimplemented request.

Unix pathname connection requires write permission on the socket inode. `SO_PEERCRED` reports the captured effective UID/GID and process ID from connection/listen or socketpair creation; subsequent identity changes do not rewrite the peer record. System V shared memory records owner and creator IDs, checks attachment/stat/control access and retains owner metadata through `IPC_SET`. The wider IPC flag and executable-mapping coverage remains in [F15](https://github.com/frankischilling/Axiom64/issues/15).

## Verification

```sh
make test-credentials-policy
make build/credentials-native build/credentials-static build/credentials-dynamic
sudo -n make test-credentials-native
make test-credentials
```

The host policy suite uses ASAN/UBSAN with allocation failure and reference-lifetime checks. It covers the maximum group list, sorting, invalid replacements, capability masks, securebits, saved/filesystem IDs, exec and DAC/signal policy.

The common C client runs against native Linux with glibc, static musl and dynamic musl. Each native run has private mount and network namespaces, a temporary RAM filesystem and its own loopback policy. It cannot change the host's routes or leave set-ID test files in the host's `/tmp`. Failures and timeouts retain logs/results and terminate the test process group.

Eight guest kernels cover static/dynamic musl, BIOS/UEFI and RAM/ext2. Actual tasks use two ordinary identities, pthread wrappers and task-local raw syscalls. Tests cover pointer faults, failed transitions, retained descriptors, traversal, sticky directories, inherited groups, chroot/symlinks, signal identity, denied tracing, raw sockets, reserved ports, ioctl/netlink mutation denial, Unix peer credentials and shared-memory control. Actual exec services verify set-UID/set-GID, no-new-privileges, ambient/bounding capabilities, execute-only interpreters and nosuid. Mount tests require noexec mapping bounds across fork, nodev and read-only failures. Every ext2 case unmounts and mounts again, checks decoded full-width ownership with actual allowed/denied users, unmounts cleanly, passes independent `e2fsck -fn`, and has its full-width owner checked by `debugfs`.

Evidence uses `build/credentials-*.log`, `build/credentials-*-results.json`, `build/credentials-results.json` and guest ext2 images. CI retains native/guest results, fsck/inode logs and the credential disk/boot fixtures. The full existing ABI, threading, storage, networking and desktop gates remain required at the same tested tree.

The fixture provides numeric identities and privileged test setup. It does not implement an account database, password authentication, a login/session manager, SSH or graphical remote access. Passing it completes a foundation for [#114](https://github.com/frankischilling/Axiom64/issues/114); the broader account, service and everyday VM requirements remain open. HP work follows completion of the required VM operating system and the project readiness review.

Linux behavior is checked against the pinned source's [identity syscalls](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/kernel/sys.c), [capability transitions](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/security/commoncap.c), [path permissions](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/fs/namei.c), [exec opening](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/fs/exec.c) and [mapped-file rights](https://github.com/torvalds/linux/blob/3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0/mm/mmap.c), together with the recorded native kernel version.
