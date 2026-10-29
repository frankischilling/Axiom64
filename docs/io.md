# Blocking I/O ownership

Axiom64 retains the open file description selected by an I/O syscall while that attempt waits. Closing or replacing its descriptor in another thread does not change its target. This follows the [Linux close contract](https://man7.org/linux/man-pages/man2/close.2.html). See [threading](threads.md) and [ABI coverage](architecture.md) for the related interfaces and limits.

## Supported operations

| Operations | Current scope |
| --- | --- |
| `read`, `write`, `readv`, `writev` | Existing regular files, pipes, Unix stream sockets, event counters, and character/block devices |
| `pread64`, `pwrite64` | Existing seekable files and block devices; preserve the shared file offset; pipes, sockets, and character devices return `ESPIPE` |
| `recvfrom`, `sendto` | Connected Unix streams, including receive-address output; a send destination is unsupported |
| `recvmsg`, `sendmsg` | Nameless Unix stream messages with copied iovec metadata; ancillary sending is unsupported and receive control length is zero |
| `accept`, `accept4` | Existing Unix listeners, optional address output, and accepted-descriptor nonblocking/close-on-exec flags |
| `flock` | [Local advisory file locks](file-locks.md), retaining the original description during an uninterrupted blocking attempt |

Socket transfers support `MSG_DONTWAIT`, receive `MSG_PEEK`, and send `MSG_NOSIGNAL`. Peeking advances across the captured vectors without consuming bytes. Unsupported transfer flags, `MSG_WAITALL`, named Unix messages, and ancillary sending return `EOPNOTSUPP`. Socket receive/send deadlines are supported as described below. Poll/select/epoll have separate wait state and are not affected by these socket options.

IPv6 raw/UDP [extended error receives](ipv6.md#extended-error-queues) use `MSG_ERRQUEUE` through the same selected description. They return immediately, own their dequeued record during user copies and keep normal receive data independent. They do not create a retained blocking receive attempt.

## Vectored transfers

`readv`, `writev`, `recvmsg` and `sendmsg` capture their vector metadata before waiting. More than 1024 vectors returns `EINVAL` for file operations and `EMSGSIZE` for message operations. Each length must fit a signed 64-bit value. Multiple vectors validate every full address span before clipping the total to `0x7ffff000` bytes; a single vector clips its length before checking the span. These rules follow [Linux v7.0 vector import](https://github.com/torvalds/linux/blob/v7.0/lib/iov_iter.c). Normal I/O and IPv6 error receives share the same bounded metadata policy.

Mapping checks apply to bytes transferred. A large valid span can return a short read or EOF without mappings for its unused tail. Regular-file copies return the completed page prefix on a later fault. Pipe and Unix stream reads keep a faulting chunk queued; bytes already copied to the destination remain visible. Writes to `/dev/null` and `/dev/zero` discard bytes without reading payload pages. Address-span validation still applies.

Empty Unix stream sends check connection and shutdown state. A broken peer returns `EPIPE` and delivers `SIGPIPE` unless `MSG_NOSIGNAL` suppresses it. An empty `writev` retains its zero-byte shortcut.

## Event counters

The Linux x86-64 `eventfd` and `eventfd2` calls create an unsigned 64-bit counter shared by duplicates, forked descriptions and retained I/O. `EFD_SEMAPHORE`, `EFD_NONBLOCK` and `EFD_CLOEXEC` are supported; unknown flags return `EINVAL`. Descriptor creation uses the current `RLIMIT_NOFILE` admission path. Final description release frees the counter, including after descriptor replacement during a blocked call.

A read requires at least eight bytes and returns exactly eight. It drains the counter, or subtracts one in semaphore mode. An empty counter blocks or returns `EAGAIN`. The counter is consumed before copying to user memory; a later page fault preserves the already copied prefix and returns `EFAULT`. `readv` can distribute that value across vectors. A write requires exactly eight bytes, rejects `UINT64_MAX`, and blocks or returns `EAGAIN` if the sum would exceed `UINT64_MAX - 1`. Zero is accepted. `writev` preserves each nonempty vector's scalar write boundary and retains completed progress and the copied pending value while blocked.

The exact write size follows [Linux v6.17](https://github.com/torvalds/linux/blob/v6.17/fs/eventfd.c). Older Linux kernels can accept the first eight bytes of a larger write; native comparisons record that version difference, while guest checks require the modern strict size. User-range checks precede the counter operation, and mapped-page faults follow the read-consumption rule above.

Poll/select/epoll report readable when the counter is nonzero and writable below the maximum. Successful writes and reads notify their applicable epoll waiters, including repeated writes while still readable. Delivery rechecks queued readiness, so draining before `epoll_wait` suppresses a stale read event. The existing single-CPU syscall discipline protects these operations; SMP synchronization remains required.

The download contract client checks flags, size and overflow boundaries, semaphore behavior, vector and page faults, ordinary-user access, resource admission, readiness, retained handle/value ownership, signals, fork/exec and close-on-exec. It runs before transfers in each native and guest download profile. Host comparisons and a counter startup test alone do not establish full HTTP/HTTPS acceptance. Kernel-generated overflow notifications, complete anonymous-inode procfs metadata and full Linux ABI conformance remain planned.

## Linux socket deadlines

`SOL_SOCKET` options `SO_RCVTIMEO_OLD`/`SO_SNDTIMEO_OLD` (20/21) and `SO_RCVTIMEO_NEW`/`SO_SNDTIMEO_NEW` (66/67) share receive/send duration state on the open socket description. On Linux x86-64, both forms use two signed 64-bit fields: seconds and microseconds. Unix streams, packet sockets, IPv4/IPv6 raw/UDP sockets and netlink route sockets use the common dispatcher in `kernel/io/socket_timeout.cpp`. Duplicates and forked descriptors share the options; a new socket description starts with infinite waits, including an accepted Unix stream.

Durations round up to the kernel's 10 ms clock units, following the jiffy conversion in [Linux v6.14](https://github.com/torvalds/linux/blob/v6.14/net/core/sock.c). A zero timeval or a duration exceeding `MAX_SCHEDULE_TIMEOUT` selects an infinite wait. A negative seconds field is accepted as an immediate timeout; invalid microseconds return `EDOM`, a short option length returns `EINVAL`, and invalid memory returns `EFAULT`. Failed setters leave the previous value intact. Getters report the rounded duration, copy at most the supplied output capacity, and update the length to the copied size.

Each supported socket I/O attempt captures one absolute monotonic deadline after importing its arguments. Changing the option through an alias does not change a waiting attempt's deadline. The first attempt can still return ready data or an immediate error. An expired wait without progress returns `EAGAIN` and releases its retained request exactly once. It does not access a buffer unmapped during an unavailable socket wait; a readable wake-up still checks the buffer and returns `EFAULT` for an invalid destination. A transferred prefix returns its byte count; it is never replayed after expiry. Nonblocking descriptions and `MSG_DONTWAIT` retain their immediate behavior. Read/readv/recv/recvmsg and accept use the receive deadline; write/writev/send/sendmsg use the send deadline. [TCP](tcp.md) also retains connect requests, uses the send deadline and returns `EINPROGRESS` on connect expiry. Full TCP interruption/deadline and retained-call acceptance remains in [TCP reliability](tcp.md).

## Kernel interface

[Packet sockets](network.md#linux-socket-contract), [IPv4 raw sockets](ipv4.md#raw-icmp-socket-contract), [UDP](udp.md), and [netlink route sockets](netlink.md#socket-ownership-and-bounds) also use retained requests. Their linked contracts describe datagram boundaries, supported named addresses, copy-fault behavior, and queue limits.

`kernel/io/io.cpp` owns request import, transfer, completion, and release behind four functions in `kernel/include/io/io.hpp`:

| Function | Contract |
| --- | --- |
| `io_syscall(Task&, const Frame&)` | Select and retain a handle, capture arguments and vector metadata, and attempt the operation. Complete immediately or save one request in the task and return `would_block`. |
| `io_resume(Task&)` | Check the retained handle and attempt a waiting operation. Return false while waiting. On completion, commit the syscall result and instruction pointer in the task's saved frame, release the request, and make the task runnable. |
| `io_discard(Task&)` | Clear and release a saved request without changing its return frame. Signal and task lifecycle code decide the resulting frame and state. Calling it without a request is harmless. |
| `io_restartable(const Task&)` | Report whether a saved operation permits automatic signal restart; a captured finite socket deadline or transferred TCP stream prefix prevents it. Inspect this before discarding the request. |
| `io_interrupted_result(const Task&)` | Capture a transferred TCP stream prefix or EINTR before releasing the interrupted request. |

The scheduler completes an operation through its retained handle rather than resolving the descriptor again. Copies use the owner's address space through the physical mapping, so completion needs no user address-space switch or kernel stack continuation. The result is committed before signal delivery; a handler cannot consume a deferred result belonging to another syscall.

Vector arrays are imported before the first attempt and retained across ordinary waits. Changes to userspace iovec metadata do not redirect the attempt. Buffer contents remain in userspace memory; each transfer validates and copies them. A copy into an unmapped output buffer returns `EFAULT`. Ordinary completed prefixes return their byte count. Blocking TCP writes and TCP MSG_WAITALL retain a prefix and cursor while waiting for queue space or more bytes, keeping the imported vector metadata and original file description; EOF, error, signal or deadline returns that prefix without replaying it. Peek uses a saved offset into unconsumed receive bytes.

TCP transfers check stream availability and errors before accessing user pages. Copies are bounded by the current user page and transfer size; an unmapped unused tail does not reject a valid short receive. A receive first peeks into a kernel buffer, copies to the user page, then consumes exactly the successfully copied bytes. A first copy fault leaves the readable queue intact, including for MSG_PEEK. An unavailable receive or full send queue preserves its deadline/nonblocking result without touching an unmapped buffer. A later fault returns a completed prefix; without logical progress it returns EFAULT. Copy boundaries can change the prefix length, while reported bytes and remaining queue ownership must agree. Native and VM comparisons check these copy and wait rules.

`tcp_write_check` checks pending errors and send capacity before source copying. The receive peek/copy/consume sequence uses the existing single-CPU syscall discipline; synchronization across that sequence remains required before SMP.

Each request retains one `Handle`, including the pipe endpoint, socket/listener, device, or inode that it owns. Completion, errors, timeout expiry, caught-signal interruption, group stop, thread/group exit, and successful exec teardown release that reference. A failed exec leaves other threads and their waiting requests intact. Closing the last retained pipe endpoint updates reader/writer counts; closing the last socket description releases its socket and wakes its peer through the normal readiness path.

Blocking TCP write/writev/send/sendmsg calls keep the transferred count and remaining cursor while the send queue is full. Completion uses the original retained description and imported vectors even after close/reuse or dup2 replacement. Blocking mode is captured at syscall entry; changing O_NONBLOCK through an alias does not convert an in-progress send or MSG_WAITALL into a different attempt. Finite send deadlines and caught signals return an already queued prefix without replaying it, including with SA_RESTART. Initially nonblocking calls and MSG_DONTWAIT return their available prefix immediately. Native and VM comparisons check this send progress; the remaining TCP reliability requirements are described in [TCP support](tcp.md).

Blocking TCP connect requests retain the original description and imported destination while the handshake remains pending, including a blocking retry of an earlier nonblocking call. Entry blocking mode survives alias flag changes and descriptor replacement. Each request captures its initial EINPROGRESS or repeated EALREADY result for finite expiry. Completion updates the socket pending state once; a failed attempt consumes its error and releases its connection storage so the same description can be used again. Native Linux comparisons cover ordinary completion, retry, binding, descriptor replacement, finite deadlines and caught-signal/restart behavior. Controlled NIC interruption, parallel retry generations and full connect acceptance remain unfinished; see [TCP support](tcp.md).

Accept/accept4 reserve the lowest available output descriptor before waiting, for TCP and Unix streams. The retained request owns this reservation through the task's file table until installation or cleanup. A full table returns EMFILE immediately, without consuming a queued child. A reserved slot has no visible file: ordinary allocation skips it, use/close returns EBADF, and raw dup2/dup3 into it returns EBUSY. Private fork/exec tables copy installed files and omit other threads' reservations. Caught-signal, deadline, error and teardown cleanup release an uninstalled slot; a successfully installed descriptor survives request cleanup. Native and VM checks verify reservation ownership and cleanup.

The slot primitives live in `kernel/fs/descriptor.cpp` with `kernel/include/fs/descriptor.hpp`. `reserve_fd` claims a slot, `install_reserved_fd` installs the owned handle, and `discard_reserved_fd` releases only an uninstalled reservation. Ordinary descriptor allocation uses the same primitives. The table remains owned by the task until its I/O request is discarded; successful exec and thread/group exit discard requests before releasing or replacing the table. This implementation uses the existing single-CPU syscall/scheduler discipline; SMP locking remains required.

## Signals and restart

A caught signal ends the waiting attempt and releases its handle before entering the handler. Without `SA_RESTART`, an attempt without progress returns `EINTR`. TCP stream transfers return a transferred prefix on interruption, with or without `SA_RESTART`, so earlier bytes cannot be replayed. With `SA_RESTART` and no finite socket deadline, its restored frame re-enters the syscall and performs a fresh descriptor lookup. A reused number can therefore select a replacement file on restart. An interrupted operation without progress and with a finite socket deadline returns `EINTR` even when the handler uses `SA_RESTART`, following [Linux's interruption and restart contract](https://man7.org/linux/man-pages/man7/signal.7.html). This differs from an uninterrupted wait, which continues through the original description. The distinction follows Linux's [syscall file lifetime](https://github.com/torvalds/linux/blob/master/fs/read_write.c) and [x86 signal restart path](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/signal.c), and is compared with Linux host execution.

Nested handlers can issue their own blocking I/O. `sigreturn` restores the appropriate completed or restart frame; jumping out of a handler leaves no retained earlier attempt. Default group stop ends saved I/O attempts. Finite socket waits without progress return `EINTR` after continue; completed TCP prefixes retain their byte count, and other saved I/O permits fresh entry. Fatal delivery and exec release waiting siblings before freeing their address spaces and shared tables. This does not establish every Linux signal, terminal or cancellation behavior.

## Verification and limits

```sh
sudo -n make test-thread-io-native
make test-thread-io
make test-threads
make test
```

The focused BIOS/UEFI profile runs static and dynamic musl tests. It checks close/dup2/reuse on blocked pipe and socket reads/writes, vectored metadata changes, send/receive messages, accept/listener lifetime, short reads, nonblocking/errors, unmapped buffers, independent fork file tables, caught and nested signals, restart, `siglongjmp`, group stop/continue, failed exec, successful exec, fatal/group exit, an exited leader with a waiting survivor, and repeated resource reuse. Endpoint `EPIPE` and EOF checks detect retained-reference leaks. Guest-only assertions require rejection of the documented unsupported socket paths; the supported cases also run on Linux as contract comparisons.

The same client checks 77 vector metadata/length cases, 24 read-copy cases, 20 write-copy cases, 16 empty-send/signal cases and 18 cross-vector chunk cases. The chunk cases cover read/write vectors and receive/send messages, leading empty vectors, copied prefixes, retained queues and short input that never reaches an invalid tail. Native runs cover both musl linkages and a separate glibc vector client. Guest runs require the complete vector marker for each linkage. Native logs and all three executables are retained with CI evidence. These cases exercise actual descriptors, mapped/unmapped pages, queued bytes, file offsets and signal delivery; they do not establish complete Linux stream or pipe conformance.

Socket timeout checks cover all ten supported operation forms, option validation and old/new aliases, dup/fork sharing, a changed option during an existing wait, descriptor replacement by a ready pipe, listener final close, four caught-signal paths with blocking handler I/O, stop/continue, successful short progress, nonblocking and independent poll waits, all four socket families, and 300 short expiry/reclamation cycles per linkage. Eight unmapped-buffer expiry cases and two readable copy-fault controls also verify final description release and leave a replacement pipe untouched. Native packet/raw tests require the corresponding privileges; unprivileged execution records explicit skips and its actual family count. CI requires all four families in privileged native runs and every guest linkage marker.

Evidence is in `build/threads-io-{bios,uefi}.log` and `build/threads-io-results.json`. The complete thread and full ABI suites also require both linkage markers. Host results do not replace guest evidence.

The implementation permits one saved I/O request per task, at most 1024 vectors, and at most `0x7ffff000` bytes per operation. Transfers use 4096-byte kernel buffers. It runs on one CPU with interrupts masked in syscalls. SMP synchronization, complete pipe atomicity and terminal behavior, full TCP/connect interruption/deadline acceptance, broader message/socket features, cancellation and complete Linux conformance remain planned.
