// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/pipe.hpp"
#include "fs/descriptor.hpp"
#include "fs/inotify.hpp"
#include "process/task.hpp"

namespace ax {
void attach_pipe(Handle& handle, Pipe& pipe) {
    handle.pipe = &pipe;
    unsigned mode = handle.flags & 3;
    if (mode != 1) {
        ++pipe.readers;
        ++pipe.reader_generation;
    }
    if (mode != 0) {
        ++pipe.writers;
        ++pipe.writer_generation;
    }
}

void detach_pipe(Handle& handle) {
    Pipe* pipe = handle.pipe;
    unsigned mode = handle.flags & 3;
    if (mode != 1)
        --pipe->readers;
    if (mode != 0)
        --pipe->writers;
    handle.pipe = nullptr;
    if (pipe->readers || pipe->writers)
        return;
    if (handle.node)
        handle.node->named_pipe = nullptr;
    release(pipe);
}

static int install(Task& task, int fd, Handle* handle) {
    install_reserved_fd(*task.files, fd, handle);
    inotify_dentry(handle->opened_dentry, inotify_open);
    return fd;
}

int64_t open_fifo(Task& task, Node* inode, Node* dentry, uint32_t flags) {
    unsigned mode = flags & 3;
    bool nonblocking = flags & 04000;
    if (mode == 3 || (flags & 040000))
        return -22;
    auto pipe = inode->named_pipe;
    if (nonblocking && mode == 1 && (!pipe || !pipe->readers))
        return -6;
    int fd = reserve_fd(task, 0, flags & 02000000);
    if (fd < 0)
        return fd;
    int error;
    auto handle = open_handle(inode, flags, &error);
    if (!handle) {
        discard_reserved_fd(*task.files, fd);
        return error;
    }
    if (!pipe) {
        pipe = static_cast<Pipe*>(alloc(sizeof(Pipe)));
        if (!pipe) {
            close_handle(handle);
            discard_reserved_fd(*task.files, fd);
            return -12;
        }
        memset(pipe, 0, sizeof(Pipe));
        inode->named_pipe = pipe;
    }
    handle->opened_dentry = dentry;
    attach_pipe(*handle, *pipe);
    bool wait_for_peer = mode == 0 ? !pipe->writers : mode == 1 && !pipe->readers;
    if (!wait_for_peer)
        return install(task, fd, handle);
    if (nonblocking) {
        handle->pipe_hangup_generation = pipe->writer_generation;
        return install(task, fd, handle);
    }
    // A peer can open and close before this task next runs.
    task.fifo_open = {handle, fd, mode == 0 ? pipe->writer_generation : pipe->reader_generation};
    task.wait = Wait::fifo_open;
    task.state = State::blocked;
    return would_block;
}

static bool peer_arrived(const FifoOpen& pending) {
    const auto handle = pending.handle;
    const auto pipe = handle->pipe;
    uint64_t generation =
        (handle->flags & 3) == 0 ? pipe->writer_generation : pipe->reader_generation;
    return generation != pending.peer_generation;
}

bool resume_fifo_open(Task& task) {
    auto pending = task.fifo_open;
    if (task.wait != Wait::fifo_open || !peer_arrived(pending))
        return false;
    task.fifo_open = {};
    task.wait = Wait::none;
    task.state = State::runnable;
    task.frame.rax = install(task, pending.fd, pending.handle);
    task.frame.rip += 2;
    return true;
}

void discard_fifo_open(Task& task) {
    auto pending = task.fifo_open;
    if (!pending.handle)
        return;
    task.fifo_open = {};
    discard_reserved_fd(*task.files, pending.fd);
    // The interrupted open never reported IN_OPEN.
    pending.handle->opened_dentry = nullptr;
    close_handle(pending.handle);
    inotify_reap_inodes();
}
} // namespace ax
