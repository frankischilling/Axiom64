# Blocking I/O ownership

Axiom64 retains the open file description selected by an I/O syscall while that attempt waits. Closing or replacing its descriptor in another thread does not change its target. This follows the [Linux close contract](https://man7.org/linux/man-pages/man2/close.2.html). See [threading](threads.md) and [ABI coverage](architecture.md) for the related interfaces and limits.

## Supported operations

| Operations | Current scope |
| --- | --- |
| `read`, `write`, `readv`, `writev` | Existing regular files, pipes, Unix stream sockets, event counters, and character/block devices |
| `splice`, `tee` | Pipe and FIFO transfers. `splice` also accepts regular RAM and ext2 files, Unix streams and datagrams, and IPv4 and IPv6 TCP and UDP sockets. |
| `vmsplice` | Transfers between userspace vectors and pipe or FIFO endpoints. |
| `pread64`, `pwrite64` | Existing seekable files and block devices; preserve the shared file offset; pipes, sockets, and character devices return `ESPIPE` |
| `recvfrom`, `sendto` | Connected Unix streams, including receive-address output; a send destination is unsupported |
| `recvmsg`, `sendmsg` | Unix stream messages with copied iovec metadata, receive source names, sender credentials and transferred file descriptions |
| `accept`, `accept4` | Existing Unix listeners, optional address output, and accepted-descriptor nonblocking/close-on-exec flags |
| `flock` | [Local advisory file locks](file-locks.md), retaining the original description during an uninterrupted blocking attempt |

Unix stream transfers support `MSG_DONTWAIT`, receive `MSG_PEEK` and `MSG_WAITALL`, send `MSG_NOSIGNAL` and receive `MSG_CMSG_CLOEXEC`. Peeking advances across the captured vectors without consuming bytes. Unsupported transfer flags return `EOPNOTSUPP`. Socket receive/send deadlines are supported as described below. Poll/select/epoll have separate wait state and are not affected by these socket options.

IPv6 raw/UDP [extended error receives](ipv6.md#extended-error-queues) use `MSG_ERRQUEUE` through the same selected description. They return immediately, own their dequeued record during user copies and keep normal receive data independent. They do not create a retained blocking receive attempt.

## Vectored transfers

`readv`, `writev`, `recvmsg` and `sendmsg` capture their vector metadata before waiting. More than 1024 vectors returns `EINVAL` for file operations and `EMSGSIZE` for message operations. Each length must fit a signed 64-bit value. Multiple vectors validate every full address span before clipping the total to `0x7ffff000` bytes; a single vector clips its length before checking the span. These rules follow [Linux v7.0 vector import](https://github.com/torvalds/linux/blob/v7.0/lib/iov_iter.c). Normal I/O and IPv6 error receives share the same bounded metadata policy.

Mapping checks apply to bytes transferred. A large valid span can return a short read or EOF without mappings for its unused tail. Regular-file copies return the completed page prefix on a later fault. Pipe and Unix stream reads keep a faulting chunk queued; bytes already copied to the destination remain visible. Writes to `/dev/null` and `/dev/zero` discard bytes without reading payload pages. Address-span validation still applies.

Empty Unix stream sends check connection and shutdown state. A broken peer returns `EPIPE` and delivers `SIGPIPE` unless `MSG_NOSIGNAL` suppresses it. An empty `writev` retains its zero-byte shortcut.

Blocking Unix writes retain their cursor and accepted byte count across queue-space waits. Each admitted interval owns its copied bytes; a copy fault commits none of the affected interval. Credentials and rights follow the [stream message contract](testing.md); transferred rights attach only to the first admitted interval. Signals, finite deadlines and peer shutdown return an accepted prefix without replaying it. A queue-space wait interrupted by shutdown returns `EPIPE` without `SIGPIPE` when no bytes were accepted. A fresh broken write retains its normal signal behavior. These distinctions follow [Linux Unix stream send](https://github.com/torvalds/linux/blob/v7.0/net/unix/af_unix.c#L2238-L2373).

## Unix stream names

Filesystem and abstract bindings are available to `getsockname`,
`getpeername` and the address result from `accept` or `accept4`. Family-only
binds request an abstract autobind. A connecting stream with `SO_PASSCRED`
also autobinds. Accepted streams retain their local name when a listener
closes, and peer queries retain the peer name when its descriptor closes.
An address-output fault during accept closes the dequeued connection and
releases the reserved descriptor.

`recvmsg` and `recvfrom` report the sender associated with the first stream
interval examined. If that sender binds after enqueue, the queued interval
sees the binding. After close or descriptor reuse, the interval still refers
to the original sender. The returned length describes the full name, even
when the caller supplies a shorter buffer. Axiom64 writes this length before
copying the address bytes, matching [Linux 7.0](https://github.com/torvalds/linux/blob/v7.0/net/socket.c#L263-L300).

A zero-byte `recvmsg` can transfer rights from its first interval while leaving
the payload queued. `MSG_PEEK` leaves the original rights queued as well.
Without control space a consuming receive discards the rights and reports
`MSG_CTRUNC`. If copying the source name faults, rights already installed by
the receive remain in the caller's descriptor table.

## Retained Unix receives

Unix `MSG_WAITALL` receives keep the original description, imported vectors,
byte cursor and first observed writer identity while waiting for more bytes.
EOF, finite expiry, a caught signal or a later copy fault returns the completed
prefix. Rights and changes of writer credentials end the receive at their
boundary. Peeks and initially nonblocking calls keep their available short
result. Message metadata is finalized when the call ends; Linux signal exits
omit credentials from a partial receive, while EOF and expiry retain them.
These rules follow [Linux Unix receive](https://github.com/torvalds/linux/blob/v7.0/net/unix/af_unix.c#L2731-L2933)
and the shared native/guest stream-wait client.

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

## Signal descriptors

`signalfd` and `signalfd4` let event loops receive blocked signals through a file
descriptor. Redirecting the descriptor's mask through an alias updates the
shared open description. A read uses the caller's pending signals, so forked
processes can use an inherited descriptor without draining their parent's queue.
Poll and select check the caller's queue. Epoll follows the signal notification
context that registered the descriptor.

Reads return complete 128-byte records. One `readv` can split a record across
vectors or drain several records. A fault consumes the signal for that record.
The read reports any complete records copied before the fault. A caught signal
can interrupt a blocking read or restart it through the normal signal path.

Standard signals coalesce. `sigqueue` and thread-directed queued sends preserve
real-time payloads and order for repeated instances of the same signal.
`signalfd`, `sigtimedwait` and signal handlers consume the same pending records.
Pending signal records share a 4,096-entry kernel pool. The receiver's
`RLIMIT_SIGPENDING` limits charged records by real UID. Real-time sends that
require a queue record return `EAGAIN` when admission fails.

## Poll and ppoll waits

`poll` and `ppoll` keep the supplied descriptor numbers and event masks while
a wait is blocked. Completion writes only the `revents` fields. Both calls
look up the retained numbers in the caller's descriptor table when checking
readiness. Ready descriptors take precedence over a pending signal.

`ppoll` accepts an optional relative timespec and a temporary signal mask.
The raw syscall writes back the remaining interval. The libc wrapper
preserves the original timespec. The kernel measures waits in 10 ms ticks.
On a process stop and continue, `poll` reimports the descriptor list and keeps
its original deadline. `ppoll` restarts with the remaining relative interval.

`make test-poll-waits` checks these behaviors for root and ordinary callers
with both musl providers and linkages on BIOS and UEFI, with additional
read-only ext2 boots. `sudo make test-poll-waits-native` runs the same cases
on Linux.

## Select and pselect waits

`select` and `pselect` retain the input fd sets across a blocked wait.
Each ready bit counts separately across read, write, and exceptional
conditions. The calls read and write whole bitmap words up to the smaller
of `nfds` and the descriptor table's current capacity. Requesting a closed
descriptor within that range returns `EBADF`. A caught signal
ends the wait without replacing the caller's fd sets.

`select` and raw `pselect6` write back the remaining relative timeout.
The libc `pselect` wrapper preserves the original timespec. The temporary
mask applies during the wait, with the original mask restored on return.
On a process stop, both waits write back the time left and restart with
that interval on continue. The wait's resolution is 10 ms.

`make test-select-waits` checks both caller identities and both musl
providers and linkages on BIOS and UEFI, with read-only ext2 coverage.
`sudo make test-select-waits-native` compares the same cases on Linux.

## Descriptor lifetime during poll and select

A blocked poll or select wait holds references to the pollable file
descriptions it registered. Closing or reusing the descriptor number
in another thread leaves the registration in place. A wakeup from the
original description prompts the wait to check the current descriptor
table. For example, a pipe reader held by a wait still permits a write
from the peer after another thread closes its descriptor. On wakeup,
`poll` reports `POLLNVAL` if the number is now closed, or reports
readiness for the description that currently occupies the number.

Unix stream sockets notify waits when data is queued and when a full
receive queue gains space. This preserves the wakeup even if another
thread consumes the data or fills the queue before the waiter runs.
Stream sockets also report the normal read and write bits and peer
write shutdown through `POLLRDHUP`.

Unix datagrams notify readers after a whole record is queued, including
zero-length records. Datagram writers get wakeups when their send budget
becomes writable or a full connected peer queue is read. A peek can wake
the waiter while the queue stays full. The send budget stays with queued records when the original socket closes
and cannot wake a replacement socket in the same slot.

These references are released when the attempt ends, including on
timeout, interruption, and task exit. `make test-descriptor-wait-lifetime`
checks all four wait syscalls on pipes and Unix stream sockets, with
BIOS, UEFI, and read-only ext2 fixtures. Use
`sudo make test-descriptor-wait-lifetime-native` for the Linux comparison.

IPv4 and IPv6 UDP sockets notify waiters when a packet enters their
receive queue or a socket error is recorded. A waiter can observe the
notification even if another thread reads the packet or clears the
error before it runs. The wakeup belongs to the socket that generated
it. `make test-udp-waits` exercises loopback packets, including
zero-length packets, and connection-refused errors across all four
wait calls. `sudo make test-udp-waits-native` runs the Linux comparison.

## Epoll descriptor lifetime

Epoll accepts descriptors with a poll operation, including pipes, sockets,
event descriptors, message queues, terminals, and selected proc controls.
Registering a regular RAM or ext2 file, a directory, or a device such as
`/dev/null` returns `EPERM`. Those descriptors still report the default
read and write readiness flags through `poll`. `O_PATH` descriptors return
`EBADF` from epoll registration.

An epoll descriptor reports anonymous-inode mode through `fstat` and
`fstatat` with `AT_EMPTY_PATH`. Reads and writes return `EINVAL`, and
positioned I/O returns `ESPIPE`. As on current Linux, `lseek` returns zero
without changing the position.

An epoll watch is keyed by the registered descriptor number and its open
file description. If another descriptor still holds that description,
closing the registered number leaves the watch in place. A new file that
reuses the number can have its own watch. The old watch goes away when the
last reference to its file description closes.

A blocked wait holds the epoll instance it entered. Closing or replacing
its descriptor in another thread leaves that wait on the original instance.
`epoll_pwait` and `epoll_pwait2` apply a temporary signal mask during the wait
and restore the previous mask afterward. `epoll_pwait2` takes a relative
`timespec` in seconds and nanoseconds. A null pointer waits indefinitely and a
zero interval checks immediately. Positive intervals round up to the scheduler's
10 ms clock, and the kernel leaves the caller's timespec untouched.
If copying a batch faults after some events, the wait returns the events it
copied and leaves the remaining events ready.

`make test-epoll-lifetime` checks duplicate and reused descriptors, fork
and exec, descriptors in queued `SCM_RIGHTS` messages, blocked waits, signal
masks, relative deadline rounding, and event copy faults. It runs both caller
identities and both musl providers and linkages on BIOS and UEFI, with
additional read-only ext2 boots.
`sudo make test-epoll-lifetime-native` runs the Linux comparison.

## Exclusive epoll wakeups

`EPOLLEXCLUSIVE` applies when adding a watch. Delete and add the watch again
to change it. The flag accepts `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`,
`EPOLLET`, and `EPOLLWAKEUP` as companion bits. Axiom64 has no system suspend
integration for `EPOLLWAKEUP`.

Ordinary watches still receive the event. Exclusive watches queue it in
registration order until one reaches a blocked epoll waiter. A watch on an
instance that is only being polled can queue the event while the notification
continues to a blocked waiter. The lifetime tests cover pipe readers, eventfd
writers, signal descriptors, and a Unix listener whose backlog is already
readable when another connection arrives.

## Nested epoll

Poll, select, and an outer epoll instance report an epoll descriptor as
readable when it has an event to deliver. A watch can span up to four links
between epoll instances. Adding a cycle or a fifth link returns `ELOOP`.
An `EPOLLEXCLUSIVE` watch on an epoll descriptor returns `EINVAL`.
Successive waits that return only part of the ready set rotate through it.

`make test-epoll-nested` checks readiness, descriptor aliases, nesting limits,
timer and signal wakeups, and rotation through ready events in the same guest
profiles as the lifetime tests. `sudo make test-epoll-nested-native` checks the
same behavior on Linux. The native comparison records the depth policy and
accounts for the tested Linux 5.15 WSL kernel accepting deeper empty chains.

## Named pipes

`mkfifo` and `mkfifoat` create a FIFO with the caller's ownership and umask.
The kernel pairs blocking opens for reading and writing. A nonblocking
reader can open an empty FIFO without a writer. A nonblocking writer needs
a reader or gets `ENXIO`. Opening with `O_RDWR` supplies both ends.

Each open of the same inode uses the same pipe, including opens through hard
links. Unlinking a name leaves open descriptions usable. Recreating the name
creates a separate FIFO. On ext2 the inode persists across reboot. Data in
the pipe lives in memory and is discarded when the last description closes.

Blocking writes to pipes and FIFOs keep the original open description and
vector positions while waiting for room. A signal or a disappearing reader
returns the bytes already copied. Closing the last reader also sends
`SIGPIPE`. A partial write to a FIFO still generates an inotify modify
event. A `writev` of at most 4096 bytes waits until the whole request
fits or returns `EAGAIN` without queuing a prefix in nonblocking mode.

`F_GETPIPE_SZ` reports the capacity shared by the endpoints of an anonymous
pipe or FIFO. `F_SETPIPE_SZ` rounds the size up to a power of two, with a
4096-byte minimum. Shrinking below the number of occupied page slots fails
with `EBUSY`. A partly consumed page still occupies its slot. `poll` and
`epoll` report writable once a slot becomes available, even though a small
write can sometimes fit in the final page of a full pipe. Resizing preserves
the queued bytes and wakes writers when it creates room. If an output
buffer faults during a read, completed slots stay consumed and the faulting
slot stays queued.

`pipe2(O_DIRECT)` enables packet mode on the write end. `F_SETFL` can change
the mode on an open pipe or FIFO description, including through a duplicate.
Packet slots hold up to 4096 bytes. A read stops at the first packet, and a
short read discards that packet's remaining bytes after a successful copy.
Zero-length reads and failed output copies leave the packet queued. A mode
change leaves existing slots in their original mode. A write can still merge
its leading remainder into a stream slot already at the end of the queue.

New pipes normally have 16 slots. The `/proc/sys/fs/pipe-max-size` setting
limits unprivileged pipe growth and initial capacity. It defaults to 1 MiB.
`pipe-user-pages-soft` defaults to 16,384 reserved pages per owning real UID.
When the soft limit would be exceeded, a new pipe starts with two slots.
`pipe-user-pages-hard` rejects new pipes and FIFO buffers that would exceed
the limit. A zero page limit disables that quota. Resizing checks growth
against the owning UID's quota. Shrinking releases the reserved pages.

`make test-named-pipes` checks descriptor replacement during a large write,
signal interruption, reader close, atomic nonblocking writes, and pipe
capacity and readiness. It grows a full pipe under a blocked writer and
checks recovery after a read buffer fault. It also checks packet boundaries,
short reads, copy faults, and mixed stream and packet writes. Guest runs check
quota enforcement, descriptor aliases, and the permissions on pipe controls.
It runs
with two caller identities and both musl providers, linkages, and firmware
types. It also verifies the same FIFO and hard link
after rebooting a writable ext2 root. `sudo make test-named-pipes-native`
runs the main workload on Linux. The `mknod` entry points currently create
regular files and FIFOs.

## Timer descriptors

`timerfd_create`, `timerfd_settime` and `timerfd_gettime` provide Linux x86-64
timer descriptors for `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME` and `CLOCK_REALTIME`.
Timers accept relative or absolute deadlines and one-shot or periodic
settings. `CLOCK_BOOTTIME` follows monotonic time while the guest has no
suspend state. Absolute realtime timers use the RTC-derived clock. Relative
timers use elapsed time. Wake-alarm clock creation returns `EPERM` on the
current platform. The wall clock has a fixed offset, so realtime clock steps
cannot cancel an armed timer on this platform.
Timers use the kernel clock's 10 ms resolution.

Reads return one 64-bit expiration count and consume it before copying, even
when a later user page faults. A partial copy returns the number of bytes
copied. `readv` can distribute the count across buffers. A drained timer is
unreadable until its next expiration. Periodic timers compute missed periods
when a reader or time query rearms them, so short periods do not increase
kernel interrupt frequency. `TFD_IOC_SET_TICKS` restores a pending count.
`poll`, `select`, and epoll report read readiness. A blocked read retains the
open file description if another thread closes or replaces the descriptor.
These behaviors follow the [Linux timerfd interface](https://github.com/torvalds/linux/blob/v7.0/fs/timerfd.c).

## Kernel interface

[Packet sockets](network.md#linux-socket-contract), [IPv4 raw sockets](ipv4.md#raw-icmp-socket-contract), [UDP](udp.md), and [netlink route sockets](netlink.md#socket-ownership-and-bounds) also use retained requests. Their linked contracts describe datagram boundaries, supported named addresses, copy-fault behavior, and queue limits.

`kernel/io/io.cpp` owns request import, transfer, completion, and release through `kernel/include/io/io.hpp`:

| Function | Contract |
| --- | --- |
| `io_syscall(Task&, const Frame&)` | Select and retain a handle, capture arguments and vector metadata, and attempt the operation. Complete immediately or save one request in the task and return `would_block`. |
| `io_resume(Task&)` | Check the retained handle and attempt a waiting operation. Return false while waiting. On completion, commit the syscall result and instruction pointer in the task's saved frame, release the request, and make the task runnable. |
| `io_discard(Task&)` | Clear and release a saved request without changing its return frame. Signal and task lifecycle code decide the resulting frame and state. Calling it without a request is harmless. |
| `io_restartable(const Task&)` | Report whether a saved operation permits automatic signal restart; a captured finite socket deadline or transferred stream prefix prevents it. Inspect this before discarding the request. |
| `io_interrupted_result(Task&)` | Finalize transferred bytes and receive metadata, or return EINTR, before releasing the interrupted request. |

The scheduler completes an operation through its retained handle rather than resolving the descriptor again. Copies use the owner's address space through the physical mapping, so completion needs no user address-space switch or kernel stack continuation. The result is committed before signal delivery; a handler cannot consume a deferred result belonging to another syscall.

Vector arrays are imported before the first attempt and retained across ordinary waits. Changes to userspace iovec metadata do not redirect the attempt. Buffer contents remain in userspace memory; each transfer validates and copies them. A copy into an unmapped output buffer returns `EFAULT`. Ordinary completed prefixes return their byte count. Blocking TCP writes and TCP MSG_WAITALL retain a prefix and cursor while waiting for queue space or more bytes, keeping the imported vector metadata and original file description; EOF, error, signal or deadline returns that prefix without replaying it. Peek uses a saved offset into unconsumed receive bytes.

TCP transfers check stream availability and errors before accessing user pages. Copies are bounded by the current user page and transfer size; an unmapped unused tail does not reject a valid short receive. A receive first peeks into a kernel buffer, copies to the user page, then consumes exactly the successfully copied bytes. A first copy fault leaves the readable queue intact, including for MSG_PEEK. An unavailable receive or full send queue preserves its deadline/nonblocking result without touching an unmapped buffer. A later fault returns a completed prefix; without logical progress it returns EFAULT. Copy boundaries can change the prefix length, while reported bytes and remaining queue ownership must agree. Native and VM comparisons check these copy and wait rules.

`tcp_write_check` checks pending errors and send capacity before source copying. The receive peek/copy/consume sequence uses the existing single-CPU syscall discipline; synchronization across that sequence remains required before SMP.

Each request holds the open descriptions it uses until completion, error, timeout, signal interruption, group stop, thread/group exit, or successful exec teardown. A failed exec leaves other threads and their waiting requests intact. Closing the last retained pipe endpoint updates reader and writer counts. Closing the last socket description releases its socket and wakes its peer through the normal readiness path.

Pipe-to-pipe `splice` moves complete slots and shares a page for a partial move.
`tee` shares the input pages and leaves the source pipe readable. Shared output
slots preserve packet boundaries and do not accept appended bytes. A blocked
transfer holds both open descriptions and returns the first available prefix.
The native and guest checks cover slot capacity, partial transfers, packet
boundaries, readiness, SIGPIPE, signal interruption, restart, and descriptor
reuse.

File-to-pipe `splice` fills non-mergeable pipe slots at file page boundaries.
Pipe-to-file `splice` consumes the written prefix, including partial packets.
It uses the waiting task's file size limit and credentials. A supplied offset
leaves the shared file position alone. A fault reading the offset prevents the
transfer. A fault writing it back returns `EFAULT` after the bytes move.

Socket `splice` copies through the existing transports. Socket offsets must be
null. Ingress keeps unread stream bytes queued and consumes any truncated
datagram. Unix stream ingress ends at a descriptor-passing boundary and
releases the attached descriptors. Pipe-to-socket transfers consume the
accepted bytes across pipe slots and keep the remaining bytes available.
Pipe availability and socket availability use separate blocking rules.
Socket waits observe the endpoint's send or receive timeout. Unix stream
ingress also checks `SPLICE_F_NONBLOCK` before waiting for socket data.
Tests cover both directions on Unix sockets and loopback TCP and UDP. They also
check Unix socket descriptor reuse, large datagrams, and send backpressure. UDP corking through
`SPLICE_F_MORE` and packet and netlink endpoints remain open.

`vmsplice` captures the vector addresses and lengths before waiting. Memory
queued into a pipe keeps a reference to each readable page until the pipe
consumes or releases it. Unmapping a queued page does not discard its bytes.
The pipe-to-memory direction copies each slot into the captured vectors. A
copy fault preserves the faulting slot and returns any completed prefix.
`SPLICE_F_NONBLOCK` controls waits. The pipe's `O_NONBLOCK` flag does not
change a `vmsplice` call. Device mappings without allocator-owned pages return
`EFAULT` when queued.

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
sudo -n make test-pipe-transfer-native
make test-pipe-transfer
make test-threads
make test
```

The focused BIOS/UEFI profile runs static and dynamic musl tests. It checks close/dup2/reuse on blocked pipe and socket reads/writes, vectored metadata changes, send/receive messages, accept/listener lifetime, short reads, nonblocking/errors, unmapped buffers, independent fork file tables, caught and nested signals, restart, `siglongjmp`, group stop/continue, failed exec, successful exec, fatal/group exit, an exited leader with a waiting survivor, and repeated resource reuse. Endpoint `EPIPE` and EOF checks detect retained-reference leaks. Guest-only assertions require rejection of the documented unsupported socket paths; the supported cases also run on Linux as contract comparisons.

The same client checks 77 vector metadata/length cases, 24 read-copy cases, 20 write-copy cases, 16 empty-send/signal cases and 18 cross-vector chunk cases. The chunk cases cover read/write vectors and receive/send messages, leading empty vectors, copied prefixes, retained queues and short input that never reaches an invalid tail. Native runs cover both musl linkages and a separate glibc vector client. Guest runs require the complete vector marker for each linkage. Native logs and all three executables are retained with CI evidence. These cases exercise actual descriptors, mapped/unmapped pages, queued bytes, file offsets and signal delivery; they do not establish complete Linux stream or pipe conformance.

Socket timeout checks cover all ten supported operation forms, option validation and old/new aliases, dup/fork sharing, a changed option during an existing wait, descriptor replacement by a ready pipe, listener final close, four caught-signal paths with blocking handler I/O, stop/continue, successful short progress, nonblocking and independent poll waits, all four socket families, and 300 short expiry/reclamation cycles per linkage. Eight unmapped-buffer expiry cases and two readable copy-fault controls also verify final description release and leave a replacement pipe untouched. Native packet/raw tests require the corresponding privileges; unprivileged execution records explicit skips and its actual family count. CI requires all four families in privileged native runs and every guest linkage marker.

Evidence is in `build/threads-io-{bios,uefi}.log` and `build/threads-io-results.json`. The complete thread and full ABI suites also require both linkage markers. Host results do not replace guest evidence.

The implementation permits one saved I/O request per task. Vectored I/O
accepts up to 1024 vectors and `0x7ffff000` bytes per request. It runs on one
CPU with interrupts masked in syscalls. Transfers between sockets and pipes,
SMP synchronization, terminal behavior, broader
TCP/connect deadline coverage, and complete Linux conformance remain planned.
