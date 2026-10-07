# Blocking I/O ownership

Axiom64 retains the open file description selected by an I/O syscall while that attempt waits. Closing or replacing its descriptor in another thread does not change its target. This follows the [Linux close contract](https://man7.org/linux/man-pages/man2/close.2.html). The implementation is tracked by [#52](https://github.com/frankischilling/Axiom64/issues/52), within the complete [threading](https://github.com/frankischilling/Axiom64/issues/5) and [ABI](https://github.com/frankischilling/Axiom64/issues/8) areas.

## Supported operations

| Operations | Current scope |
| --- | --- |
| `read`, `write`, `readv`, `writev` | Existing regular files, pipes, Unix stream sockets, and character/block devices |
| `pread64`, `pwrite64` | Existing seekable files and block devices; preserve the shared file offset; pipes, sockets, and character devices return `ESPIPE` |
| `recvfrom`, `sendto` | Connected Unix streams, including receive-address output; a send destination is unsupported |
| `recvmsg`, `sendmsg` | Nameless Unix stream messages with copied iovec metadata; ancillary sending is unsupported and receive control length is zero |
| `accept`, `accept4` | Existing Unix listeners, optional address output, and accepted-descriptor nonblocking/close-on-exec flags |

Socket transfers support `MSG_DONTWAIT`, receive `MSG_PEEK`, and send `MSG_NOSIGNAL`. Peeking advances across the captured vectors without consuming bytes. Unsupported transfer flags, `MSG_WAITALL`, named messages, and ancillary sending return `EOPNOTSUPP`. Socket receive/send timeout options remain unsupported and return `ENOPROTOOPT`; there is no accepted I/O deadline requiring a retained request. Poll/select/epoll have separate wait state and are not handled by this module.

## Kernel interface

`kernel/io/io.cpp` owns request import, transfer, completion, and release behind three functions in `kernel/include/io/io.hpp`:

| Function | Contract |
| --- | --- |
| `io_syscall(Task&, const Frame&)` | Select and retain a handle, capture arguments and vector metadata, and attempt the operation. Complete immediately or save one request in the task and return `would_block`. |
| `io_resume(Task&)` | Check the retained handle and attempt a waiting operation. Return false while waiting. On completion, commit the syscall result and instruction pointer in the task's saved frame, release the request, and make the task runnable. |
| `io_discard(Task&)` | Clear and release a saved request without changing its return frame. Signal and task lifecycle code decide the resulting frame and state. Calling it without a request is harmless. |

The scheduler completes an operation through its retained handle rather than resolving the descriptor again. Copies use the owner's address space through the physical mapping, so completion needs no user address-space switch or kernel stack continuation. The result is committed before signal delivery; a handler cannot consume a deferred result belonging to another syscall.

Vector arrays are imported before the first attempt and retained across ordinary waits. Changes to userspace iovec metadata do not redirect the attempt. Buffer contents remain in userspace memory; each transfer validates and copies them. An unmapped output buffer returns `EFAULT`. Completed prefixes return their byte count and do not leave the task blocked or replay earlier bytes.

Each request retains one `Handle`, including the pipe endpoint, socket/listener, device, or inode that it owns. Completion, errors, caught-signal interruption, group stop, thread/group exit, and successful exec teardown release that reference. A failed exec leaves other threads and their waiting requests intact. Closing the last retained pipe endpoint updates reader/writer counts; closing the last socket description releases its socket and wakes its peer through the normal readiness path.

## Signals and restart

A caught signal ends the waiting attempt and releases its handle before entering the handler. Without `SA_RESTART`, the saved syscall returns `EINTR`. With `SA_RESTART`, its restored frame re-enters the syscall and performs a fresh descriptor lookup. A reused number can therefore select a replacement file on restart. This differs from an uninterrupted wait, which continues through the original description. The distinction follows Linux's [syscall file lifetime](https://github.com/torvalds/linux/blob/master/fs/read_write.c) and [x86 signal restart path](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/signal.c), and is compared with Linux host execution.

Nested handlers can issue their own blocking I/O. `sigreturn` restores the appropriate completed or restart frame; jumping out of a handler leaves no retained earlier attempt. Default group stop ends saved I/O attempts and permits fresh entry after continue. Fatal delivery and exec release waiting siblings before freeing their address spaces and shared tables. This does not establish every Linux signal, terminal, cancellation, or timeout behavior.

## Verification and limits

```sh
make test-thread-io
make test-threads
make test
```

The focused BIOS/UEFI profile runs static and dynamic musl tests. It checks close/dup2/reuse on blocked pipe and socket reads/writes, vectored metadata changes, send/receive messages, accept/listener lifetime, short reads, nonblocking/errors, unmapped buffers, independent fork file tables, caught and nested signals, restart, `siglongjmp`, group stop/continue, failed exec, successful exec, fatal/group exit, an exited leader with a waiting survivor, and repeated resource reuse. Endpoint `EPIPE` and EOF checks detect retained-reference leaks. Guest-only assertions require rejection of the documented unsupported socket paths; the supported cases also run on Linux as contract comparisons.

Evidence is in `build/threads-io-{bios,uefi}.log` and `build/threads-io-results.json`. The complete thread and full ABI suites also require both linkage markers. Host results do not replace guest evidence.

The implementation permits one saved I/O request per task, at most 1024 vectors, and at most `0x7ffff000` bytes per operation. Transfers use 4096-byte kernel buffers. It runs on one CPU with interrupts masked in syscalls. SMP synchronization, complete pipe atomicity and terminal behavior, socket deadlines, broader message/socket features, cancellation, and complete Linux conformance remain planned.
