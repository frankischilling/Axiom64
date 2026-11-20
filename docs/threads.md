# Threads and futexes

Axiom64 runs Linux x86-64 musl pthreads on one CPU. Threads share selected process resources and retain their own TID, registers, FS base, FPU state, signal mask, alternate stack, and wait state.

## Resource ownership

| Resource | Lifetime and sharing |
| --- | --- |
| `MemoryContext` | Page tables, allocation cursor, brk, and SysV attachments; shared by `CLONE_VM`, released after its final task reference |
| `FileTable` | Descriptor slots and close-on-exec flags; shared by `CLONE_FILES`; copied tables retain the same open file descriptions |
| `FsContext` | Working-directory identity and umask; shared by `CLONE_FS` |
| `SignalHandlers` | Signal dispositions; shared by `CLONE_SIGHAND`, with independent per-thread masks |
| `Process` | TGID, parent, session/group, controlling terminal, executable path, alarms, process signals, and live-thread count |
| `Task` | TID, saved CPU state, TLS, thread signals, and blocking operation |

`getpid` returns the TGID and `gettid` returns the calling task's TID. `exit` releases one thread; `exit_group` terminates the group. An exited leader retains a wait record while its other threads run. The parent can reap the process only after its final thread exits. Nonleader slots are reusable immediately after exit. Clear-child-TID writes zero and wakes a shared futex waiter on exit or successful exec.

Fork copies private pages, retains shared pages, and creates a process containing only the caller. Vfork shares memory and suspends the calling task until the child exits or execs. Successful exec terminates other threads in the group, gives a surviving worker the TGID, replaces memory, and unshares descriptor and signal-handler tables before applying close-on-exec and disposition resets. Loading or allocation failure preserves the existing process.

Executable arguments and environment strings are captured into owned buffers before loading. Each string allows 131,072 bytes including its terminator, with a 6 MiB combined budget. Empty argument vectors produce one empty argument. The loader checks the complete aligned stack, auxiliary vector and string layout before replacing the process; invalid pointers, excessive input and allocation failures leave its original memory, credentials, descriptors and threads intact. The VFS path limit remains 1,023 bytes. Runtime stack-limit changes and complete resource-limit enforcement remain planned.

`waitid` selects all children, one PID or a process group and reports exited, stopped and continued events. `WNOHANG` returns immediately; `WNOWAIT` retains the selected event and exited child's identity for a later wait. Blocking waits wake when a matching child changes state or another thread reaps it. A failed result copy consumes an ordinary event but preserves one observed with `WNOWAIT`. The kernel writes the documented child fields of `siginfo_t`, leaving its unused tail untouched. PID descriptors and tracing-specific flags remain unsupported; child CPU usage remains zero until accounting is implemented.

`/proc/PID/stat` and `/proc/PID/task/TID/stat` expose 52 fields, including each process or thread's actual birth time in 100 Hz ticks. Process birth survives a nonleader exec; other accounting, address and terminal fields remain incomplete. `/proc/sys/kernel/random/boot_id` returns one secure UUID for the kernel lifetime and returns `EAGAIN` before entropy initialization. This early-boot rule is stricter than Linux's UUID policy. Regular procfs reads return that error directly rather than entering a stream wait.

`sudo -n make test-waitid-native test-proc-identity-native test-exec-arguments-native` runs six native provider/linkage profiles for each interface. The matching guest targets run both musl providers and linkages under BIOS and UEFI. Process identity also checks eight entropy-unready boots and compares UUIDs across independent ready kernels. Sanitizer targets exercise actual procfs serialization and executable capture allocation/copy failures. Guest tests verify long arguments, boundary errors, preserved failed-exec state, child selectors, stop/continue, signals, restarts and protected unused result bytes.

## Parent death and synchronous signal waits

`PR_SET_PDEATHSIG` and `PR_GET_PDEATHSIG` store the selected signal in the calling task. Fork and thread creation reset it. The creator thread's exit delivers the configured signal even while other threads in that process remain alive. A worker that becomes the process leader at exec retains its child relationships. Effective/filesystem UID or GID changes, permitted-capability gains and privileged exec clear the setting; ordinary exec preserves it. These transitions follow [Linux parent-death handling](https://github.com/torvalds/linux/blob/v6.17/kernel/exit.c).

`rt_sigtimedwait` captures an eight-byte signal mask and an optional valid relative timeout. It selects thread-pending signals before shared process signals and synchronous fault numbers before other numbers. Timeout returns EAGAIN; caught signals return EINTR even with SA_RESTART. An invalid siginfo destination consumes the selected signal before returning EFAULT. Standard signals coalesce while preserving the first sender's information. Full queues for repeated real-time signals remain unfinished. The observable rules follow [Linux signal waiting](https://github.com/torvalds/linux/blob/v6.17/kernel/signal.c).

`sudo -n make test-parent-death-native test-signal-wait-native` compares six native provider/linkage profiles. `make test-parent-death test-signal-wait` runs eight BIOS/UEFI guest profiles per interface. The retained cases include creator-thread exit, worker exec, credential transitions, 128 reuse cycles, signal ordering, failed copies, delayed ignored signals, relative and saturated timeouts, restart denial and stop/continue interruption.

## Clone interface

The x86-64 `clone` syscall accepts these flags:

| Flag | Behavior |
| --- | --- |
| `CLONE_VM`, `CLONE_FS`, `CLONE_FILES` | Share the corresponding resource |
| `CLONE_SIGHAND` | Share dispositions; requires `CLONE_VM` |
| `CLONE_THREAD` | Join the caller's group; requires shared memory/dispositions and no exit signal |
| `CLONE_SETTLS` | Install the supplied FS base |
| `CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID` | Write the new TID to validated parent/child pointers |
| `CLONE_CHILD_CLEARTID` | Register the child pointer for exit/exec clearing and wakeup |
| `CLONE_VFORK` | Suspend the caller; requires shared memory and a separate process |
| `CLONE_SYSVSEM` | Share the System V semaphore undo list. The last owner to exit applies the adjustments. |
| `CLONE_DETACHED` | Accepted and ignored for Linux compatibility |

Separate process children require `SIGCHLD`. Shared-memory creation requires a child stack except for vfork. Invalid supported combinations return `EINVAL`; invalid stack/TID pointers return `EFAULT`. Unsupported flags, other process exit signals, and `clone3` return `ENOSYS`. This interface does not implement every Linux clone mode.

## Futex interface

| Operation | Behavior |
| --- | --- |
| `FUTEX_WAIT` | Atomically compare a 32-bit word and queue; optional relative timeout |
| `FUTEX_WAKE` | Wake matching waiters and return the actual count |
| `FUTEX_WAIT_BITSET` | Compare and queue with a nonzero mask; optional absolute timeout |
| `FUTEX_WAKE_BITSET` | Wake waiters whose mask intersects the requested mask |
| `FUTEX_REQUEUE` | Wake a bounded number and move additional waiters to another key |
| `FUTEX_CMP_REQUEUE` | Check the source value before waking/requeuing |

`FUTEX_PRIVATE_FLAG` keys words by memory-context identity and virtual address. Shared operations key the current resident physical page and offset. A queued shared waiter retains its backing page; unmapping and reusing the same virtual address cannot turn a new allocation into the old wait key. Requeue retains the destination before releasing the old page. This identity model covers the current eager-copy/shared-page mappings; demand paging, COW, and broader file mapping support need a corresponding identity design.

Syscalls mask interrupts on the single CPU, so no user writer or waker can run between the expected-value check and queue insertion. This must be replaced with appropriate kernel synchronization before SMP. Waits return `EAGAIN` for a mismatched word, `ETIMEDOUT` at their deadline, and `EINTR` when a caught signal interrupts them. Words must be aligned, readable, and mapped for waits and shared operations; invalid addresses return `EFAULT`. Device mappings are rejected. Invalid times or zero bitset masks return `EINVAL`. Private wake/requeue keys can name an unmapped virtual address. Requeue returns the number woken plus moved and rejects negative counts. Legacy wake follows Linux's signed-limit behavior, which can wake one waiter even when the supplied count is nonpositive.

Timeouts use the existing 100 Hz elapsed clock. Absolute `FUTEX_WAIT_BITSET` waits with `FUTEX_CLOCK_REALTIME` convert the UTC deadline into remaining monotonic time; relative waits retain elapsed-time semantics. The [boot calendar](time.md#boot-calendar) supplies realtime, and realtime clock setting remains pending. Requeue preserves deadlines and bitsets. Default process stop/continue controls all live members, process-directed signals can be delivered to an unmasked member, and `tkill`/`tgkill` address individual threads.

## Verification

```sh
make test-threads
make test-thread-io
python3 scripts/boot_test.py --suite threads --phase cond --firmware both --timeout 30
make test
```

The dedicated suite boots both BIOS and UEFI. It requires static and dynamic musl tests for create/join/detach, TLS and FPU isolation, shared cwd/umask/descriptors, contended mutexes, producer/consumer condition broadcasts, semaphores, and timed waits. Repeated creation exceeds the fixed task-slot count. Direct futex tests cover bitset selection, comparison/requeue, interruption, mapping aliases, unmap/remap backing lifetime, and cross-process wakeups.

Lifecycle tests exercise blocked group teardown, a surviving worker after leader exit, stop/continue, final-thread status, fork and exec from workers, and raw clone resource/TID flags. An assembly test helper invokes the kernel clone interface independently of libc wrapper restrictions. The guest GNU C++ toolchain builds and runs a contended `std::thread`/mutex/condition-variable queue and a condition timeout. The full suite also requires these thread tests alongside ABI, signals, mounts, compilers, desktop, and input checks; storage and ext2 retain separate matrices.

[Blocking I/O tests](io.md#verification-and-limits) additionally check retained pipe/socket descriptions across close/dup2/reuse, copied vector metadata, accept, nested signal I/O, fresh lookup on restart, abandoned handlers, failed/successful exec, fatal exit, and repeated endpoint cleanup. They run in both linkage modes in the complete suites, with a separate focused profile.

Evidence is saved in `build/threads-all-{bios,uefi}.log` and `build/threads-all-results.json`. The condition-only profile writes `threads-cond-*` evidence and the I/O profile writes `threads-io-*`. Host execution of a test program is a contract comparison and does not replace guest evidence.

## System V semaphores

`semget`, `semctl`, `semop`, and `semtimedop` support keyed and private sets.
An operation vector changes the set atomically. Blocked calls keep their original
vector, and a timeout or caught signal ends the wait without applying its operations.
Removing a set wakes its waiters with `EIDRM`. A regular fork starts with an empty
undo list. `CLONE_SYSVSEM` shares the caller's list, and `SETVAL` and `SETALL`
clear pending adjustments for the affected members.

`make test-system-v-semaphores` checks both musl providers and linkages on BIOS
and UEFI as root and UID 65534. `sudo make test-system-v-semaphores-native`
runs the matching Linux workload in isolated IPC namespaces. Both retain logs
and compiler inputs with the tested executable.

## System V message queues

`msgget`, `msgsnd`, `msgrcv`, and `msgctl` support private and keyed queues
on x86-64. Receivers can select the first message, an exact or excluded type,
the lowest type up to a limit, or a queue position for a nondestructive
`MSG_COPY`. `MSG_NOERROR` truncates a destructive read. `E2BIG` leaves the
message queued, and a user-buffer fault after a destructive read consumes it.

Queues retain messages across process exit and exec until a receiver takes them
or an owner removes the queue. A blocked sender keeps the imported payload while
waiting for capacity. A caught signal returns `EINTR`, and queue removal returns
`EIDRM` to sleeping callers. Owner, creator and group permissions govern access,
and `msgctl` reports ownership, limits, usage and send/receive metadata.

`make test-system-v-message-queues` exercises both musl providers and linkages
on BIOS and UEFI as root and UID 65534. `sudo make test-system-v-message-queues-native`
runs the same workload in isolated Linux IPC namespaces. Axiom64 uses one global
IPC scope with fixed defaults of 32,000 queues, 8,192 bytes per message, and
16,384 bytes of capacity on a new queue. IPC namespaces and Linux IPC sysctls
remain unimplemented.

## System V shared memory

`shmat` maps a segment into the caller's address space. Separate mappings and
forked processes share the same backing pages. Read-only attachments cannot
gain write access through `mprotect`. `SHM_REMAP` can replace an existing
range, and `shmdt` removes only the surviving fragments of the selected
attachment. Anonymous or file mappings added in the gaps stay mapped.

`IPC_RMID` releases the key immediately. A marked segment remains accessible
by ID until its last mapping goes away through unmap, detach, exec, or exit.
`shmctl` reports wall-clock timestamps, mapping counts, owners, and usage.
`SHM_LOCK` accounts for the caller's locked-memory limit. Axiom64 keeps segment
pages resident and supports up to 4,096 segments of up to 64 MiB each,
subject to available memory. Huge pages and IPC namespaces remain unimplemented.

`make test-system-v-shared-memory` checks mappings, fork and exec, removal,
permissions, and executable attachments as root and UID 65534 on BIOS and
UEFI with both musl providers and linkages. The matching Linux comparison runs
with `sudo make test-system-v-shared-memory-native`.

## POSIX semaphores

The kernel mounts a volatile, root-owned `/dev/shm` on both RAM and ext2
roots. Its sticky permissions let ordinary users create named semaphores
and protect other owners' names from removal. Programs use the libc
`sem_open` and `sem_unlink` interfaces. Unlinking removes the name while
existing mappings remain usable. Process-shared unnamed semaphores use
shared mappings and futexes.

`make test-posix-semaphores` checks expiration, signal restart, fork and exec,
exclusive creation, and name permissions. It runs as root and UID 65534
with both musl providers and linkages on BIOS and UEFI RAM boots. It also
runs the build-provider static client from a read-only ext2 root on both
firmware types. `sudo make test-posix-semaphores-native` compares the same
workload on Linux with a private `/dev/shm` mount.

## POSIX message queues

POSIX message queues use ordinary file descriptors and appear under
`/dev/mqueue`. Messages arrive from highest to lowest priority, in send
order within each priority. Unlinking removes the name while open
descriptions and waiting calls keep the queue alive.

`mq_timedsend` and `mq_timedreceive` use absolute realtime deadlines.
`O_NONBLOCK` belongs to the open description, so descriptor aliases share it.
Poll and epoll report queued messages and available capacity. Queue limits
include the creator's `RLIMIT_MSGQUEUE` budget. One-shot notification
supports signals with sender information and libc thread callbacks over
netlink.

`make test-posix-message-queues` exercises both caller identities with both
musl providers and linkages on BIOS and UEFI. It also boots a read-only ext2
root under both firmware types. `sudo make test-posix-message-queues-native`
runs the same client in a private Linux IPC namespace. IPC namespace
creation and runtime queue sysctls remain unimplemented.

## POSIX asynchronous I/O

Both musl providers run POSIX AIO in userspace. Their worker threads use
Axiom64's file and pipe operations, futexes, and queued signals. Programs link
with `-pthread -lrt` and use the standard `<aio.h>` interface.

`make test-posix-aio` covers positioned reads and writes, both `aio_fsync`
modes, errors on read-only descriptors, and `LIO_WAIT` and `LIO_NOWAIT` lists.
It checks signal payloads for single requests and thread callbacks for
individual requests and lists. A pending pipe read demonstrates timeout, interruption and
cancellation with notification. A separate test closes and reuses the same
descriptor number while checking that the old operation cannot take data
from the replacement pipe.

The workload runs as root and UID 65534 with both musl providers and both
linkages on BIOS and UEFI. Read-only ext2 boots also read the test executable
with AIO. Writable tests use volatile `/dev/shm`. `sudo make test-posix-aio-native`
compares the same workload with Linux glibc, where an in-flight operation
that cannot be cancelled must still finish on its original file description.

## Remaining work

The limit is one CPU, 64 task slots, and 128 descriptors per file table. FPU switching uses FXSAVE/FXRSTOR for x87/SSE state, without extended XSAVE state. An untimed futex wait honors `SA_RESTART`. A caught signal interrupts a timed futex wait with `EINTR`.

Robust owner-death lists, priority inheritance, `FUTEX_WAKE_OP`, newer wait-vector operations, cancellation coverage, rwlocks/barriers, complete process-shared POSIX synchronization, thread-targeted timers, full fork/exec/signal semantics, and complete resource limits remain unfinished. Working musl and C++ tests do not establish complete POSIX threading or Linux compatibility. [SMP](feature-roadmap.md#f07-smp-scheduling-and-kernel-synchronization) follows the tested single-CPU interface.
