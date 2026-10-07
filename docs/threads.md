# Threads and futexes

Axiom64 runs Linux x86-64 musl pthreads on one CPU. Threads share selected process resources and retain their own TID, registers, FS base, FPU state, signal mask, alternate stack, and wait state. This is the first implementation slice of [the threading area](https://github.com/frankischilling/Axiom64/issues/5), tracked by [#47](https://github.com/frankischilling/Axiom64/issues/47).

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
| `CLONE_SYSVSEM`, `CLONE_DETACHED` | Accepted for musl; SysV semaphore undo is not implemented and detached is ignored |

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

Timeouts use the existing 100 Hz boot-relative clocks. `FUTEX_CLOCK_REALTIME` is accepted for waits; realtime and monotonic currently share the same boot epoch. Requeue preserves deadlines and bitsets. Default process stop/continue controls all live members, process-directed signals can be delivered to an unmasked member, and `tkill`/`tgkill` address individual threads.

## Verification

```sh
make test-threads
python3 scripts/boot_test.py --suite threads --phase cond --firmware both --timeout 30
make test
```

The dedicated suite boots both BIOS and UEFI. It requires static and dynamic musl tests for create/join/detach, TLS and FPU isolation, shared cwd/umask/descriptors, contended mutexes, producer/consumer condition broadcasts, semaphores, and timed waits. Repeated creation exceeds the fixed task-slot count. Direct futex tests cover bitset selection, comparison/requeue, interruption, mapping aliases, unmap/remap backing lifetime, and cross-process wakeups.

Lifecycle tests exercise blocked group teardown, a surviving worker after leader exit, stop/continue, final-thread status, fork and exec from workers, and raw clone resource/TID flags. An assembly test helper invokes the kernel clone interface independently of libc wrapper restrictions. The guest GNU C++ toolchain builds and runs a contended `std::thread`/mutex/condition-variable queue and a condition timeout. The full suite also requires these thread tests alongside ABI, signals, mounts, compilers, desktop, and input checks; storage and ext2 retain separate matrices.

Evidence is saved in `build/threads-all-{bios,uefi}.log` and `build/threads-all-results.json`. The condition-only profile writes `threads-cond-*` evidence. Host execution of a test program is a contract comparison and does not replace guest evidence.

## Remaining work

The limit is one CPU, 64 task slots, and 128 descriptors per file table. FPU switching uses FXSAVE/FXRSTOR for x87/SSE state, without extended XSAVE state. Caught signals currently return `EINTR` from futex waits even with `SA_RESTART`.

Robust owner-death lists, priority inheritance, `FUTEX_WAKE_OP`, newer wait-vector operations, cancellation coverage, rwlocks/barriers, complete process-shared POSIX synchronization, thread-targeted timers, and full fork/exec/signal semantics remain in #5 and its related areas. SysV semaphore undo and complete resource limits are also pending. Working musl and C++ tests do not establish complete POSIX threading or Linux compatibility. [SMP](https://github.com/frankischilling/Axiom64/issues/7) follows the tested single-CPU interface.
