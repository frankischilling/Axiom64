// SPDX-License-Identifier: GPL-3.0-or-later
/** @file Pipe page queues, capacity ownership, and FIFO rendezvous. */
#include "fs/pipe.hpp"
#include "io/descriptor_wait.hpp"
#include "fs/descriptor.hpp"
#include "fs/inotify.hpp"
#include "ipc/ipc.hpp"
#include "process/task.hpp"

namespace ax {
static constexpr unsigned default_pipe_pages = 16;
static constexpr unsigned pipe_user_pages_soft = 16384;
static constexpr uint32_t unprivileged_pipe_bytes = 1024 * 1024;
static Pipe* live_pipes;

static unsigned reserved_pages(uint32_t owner) {
    unsigned total = 0;
    for (auto pipe = live_pipes; pipe; pipe = pipe->next)
        if (pipe->owner == owner)
            total += pipe->capacity;
    return total;
}

static bool pipe_quota_applies(const Credentials& credentials) {
    return !capable(credentials, Capability::sys_resource) &&
           !capable(credentials, Capability::sys_admin);
}

Pipe* create_pipe_buffer(const Credentials& credentials) {
    auto pipe = static_cast<Pipe*>(alloc(sizeof(Pipe)));
    if (!pipe)
        return nullptr;
    *pipe = {};
    pipe->owner = credentials.user.real;
    pipe->capacity = default_pipe_pages;
    if (pipe_quota_applies(credentials) &&
        reserved_pages(pipe->owner) + default_pipe_pages > pipe_user_pages_soft)
        pipe->capacity = 2;
    pipe->slots = static_cast<PipeSlot*>(alloc(pipe->capacity * sizeof(PipeSlot)));
    if (!pipe->slots) {
        release(pipe);
        return nullptr;
    }
    pipe->next = live_pipes;
    live_pipes = pipe;
    return pipe;
}

void destroy_pipe_buffer(Pipe& pipe) {
    auto link = &live_pipes;
    while (*link != &pipe)
        link = &(*link)->next;
    *link = pipe.next;
    for (unsigned i = 0; i < pipe.occupied; ++i)
        page_free(pipe.slot(i).page);
    release(pipe.slots);
    release(&pipe);
}

int64_t pipe_fcntl(Handle& handle, unsigned command, uint32_t size,
                   const Credentials& credentials) {
    auto pipe = handle.pipe;
    if (!pipe)
        return -9;
    if (command == 1032) // F_GETPIPE_SZ
        return pipe->capacity * page_size;
    if (size > (1u << 31))
        return -22;
    unsigned capacity = 1;
    while (capacity * page_size < size)
        capacity *= 2;
    if (capacity > pipe->capacity) {
        if (capacity * page_size > unprivileged_pipe_bytes &&
            !capable(credentials, Capability::sys_resource))
            return -1;
        if (pipe_quota_applies(credentials) &&
            reserved_pages(pipe->owner) - pipe->capacity + capacity > pipe_user_pages_soft)
            return -1;
    }
    if (capacity < pipe->occupied)
        return -16;
    if (capacity != pipe->capacity) {
        auto slots = static_cast<PipeSlot*>(alloc(capacity * sizeof(PipeSlot)));
        if (!slots)
            return -12;
        for (unsigned i = 0; i < pipe->occupied; ++i)
            slots[i] = pipe->slot(i);
        release(pipe->slots);
        pipe->slots = slots;
        pipe->capacity = capacity;
        pipe->first = 0;
    }
    epoll_notify(&handle, 4 | 0x100);
    return capacity * page_size;
}

int64_t pipe_write(Handle& handle, const void* data, size_t count, bool merge_tail) {
    auto& pipe = *handle.pipe;
    if (!merge_tail) {
        uint64_t page = page_alloc();
        if (!page)
            return -12;
        pipe.slot(pipe.occupied++) = {page, 0, 0, bool(handle.flags & pipe_direct)};
    }
    auto& slot = pipe.slot(pipe.occupied - 1);
    memcpy(static_cast<uint8_t*>(physical(slot.page)) + slot.end, data, count);
    slot.end += count;
    pipe.size += count;
    epoll_notify(&handle, 1 | 0x40);
    return count;
}

int64_t pipe_read(Pipe* pipe, void* buffer, size_t length, bool peek) {
    if (!length)
        return 0;
    if (!pipe->size)
        return pipe->writers ? -11 : 0;
    auto bytes = static_cast<uint8_t*>(buffer);
    bool was_full = pipe->full();
    unsigned removed = 0;
    size_t copied = 0;
    size_t consumed = 0;
    for (unsigned index = 0; index < pipe->occupied && copied < length; ++index) {
        auto& slot = pipe->slot(index);
        size_t available = slot.end - slot.begin;
        size_t part = min(length - copied, available);
        memcpy(bytes + copied, static_cast<const uint8_t*>(physical(slot.page)) + slot.begin, part);
        copied += part;
        if (!peek) {
            if (slot.packet || part == available) {
                consumed += available;
                page_free(slot.page);
                ++removed;
            } else {
                consumed += part;
                slot.begin += part;
            }
        }
        if (slot.packet)
            break;
    }
    if (!peek) {
        pipe->size -= consumed;
        pipe->first = (pipe->first + removed) & (pipe->capacity - 1);
        pipe->occupied -= removed;
        if (was_full && removed)
            descriptor_wait_notify(pipe, 4 | 0x100);
    }
    return copied;
}

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
    if (pipe->readers || pipe->writers) {
        if (!pipe->readers || !pipe->writers)
            descriptor_wait_notify(pipe, 0);
        return;
    }
    if (handle.node)
        handle.node->named_pipe = nullptr;
    destroy_pipe_buffer(*pipe);
}

static int install(Task& task, int fd, Handle* handle) {
    install_reserved_fd(*task.files, fd, handle);
    inotify_dentry(handle->opened_dentry, inotify_open);
    return fd;
}

int64_t open_fifo(Task& task, Node* inode, Node* dentry, uint32_t flags) {
    unsigned mode = flags & 3;
    bool nonblocking = flags & 04000;
    if (mode == 3 || (flags & pipe_direct))
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
        pipe = create_pipe_buffer(task.credentials);
        if (!pipe) {
            close_handle(handle);
            discard_reserved_fd(*task.files, fd);
            return -12;
        }
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
