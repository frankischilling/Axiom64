// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/pipe.cpp
 * @brief   Pipes and FIFO buffers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages page-backed queues, capacity limits, packet boundaries, and FIFO
 * endpoint rendezvous.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "fs/pipe.hpp"
#include "io/descriptor_wait.hpp"
#include "fs/descriptor.hpp"
#include "fs/inotify.hpp"
#include "ipc/ipc.hpp"
#include "process/task.hpp"

namespace ax {
static constexpr unsigned default_pipe_pages = 16;
static uint64_t pipe_user_pages_soft = 16384;
static uint64_t pipe_user_pages_hard;
static uint32_t unprivileged_pipe_bytes = 1024 * 1024;
static Pipe* live_pipes;

static uint32_t rounded_size(uint32_t size) {
    if (size > (1u << 31))
        return 0;
    uint32_t bytes = page_size;
    while (bytes < size)
        bytes *= 2;
    return bytes;
}

uint64_t pipe_limit(PipeLimit limit) {
    switch (limit) {
    case PipeLimit::max_size:
        return unprivileged_pipe_bytes;
    case PipeLimit::hard_pages:
        return pipe_user_pages_hard;
    case PipeLimit::soft_pages:
        return pipe_user_pages_soft;
    }
    panic("invalid pipe limit");
}

int set_pipe_limit(PipeLimit limit, uint64_t value) {
    switch (limit) {
    case PipeLimit::max_size: {
        uint32_t bytes = rounded_size(uint32_t(value));
        if (!bytes)
            return -22;
        unprivileged_pipe_bytes = bytes;
        return 0;
    }
    case PipeLimit::hard_pages:
        pipe_user_pages_hard = value;
        return 0;
    case PipeLimit::soft_pages:
        pipe_user_pages_soft = value;
        return 0;
    }
    panic("invalid pipe limit");
}

static uint64_t reserved_pages(uint32_t owner) {
    uint64_t total = 0;
    for (auto pipe = live_pipes; pipe; pipe = pipe->next)
        if (pipe->owner == owner)
            total += pipe->capacity;
    return total;
}

static bool pipe_quota_applies(const Credentials& credentials) {
    return !capable(credentials, Capability::sys_resource) &&
           !capable(credentials, Capability::sys_admin);
}

static bool exceeds_limit(uint64_t pages, uint64_t limit) {
    return limit && pages > limit;
}

Pipe* create_pipe_buffer(const Credentials& credentials, int& error) {
    uint32_t owner = credentials.user.real;
    unsigned capacity = default_pipe_pages;
    if (!capable(credentials, Capability::sys_resource))
        capacity = min(capacity, unsigned(unprivileged_pipe_bytes / page_size));
    if (pipe_quota_applies(credentials)) {
        uint64_t reserved = reserved_pages(owner);
        if (exceeds_limit(reserved + capacity, pipe_user_pages_soft))
            capacity = 2;
        if (exceeds_limit(reserved + capacity, pipe_user_pages_hard)) {
            error = -23; // ENFILE for pipe(), translated to ENOMEM for FIFO opens.
            return nullptr;
        }
    }
    error = -12;
    auto pipe = static_cast<Pipe*>(alloc(sizeof(Pipe)));
    if (!pipe)
        return nullptr;
    *pipe = {};
    pipe->owner = owner;
    pipe->capacity = capacity;
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
    uint32_t bytes = rounded_size(size);
    if (!bytes)
        return -22;
    unsigned capacity = bytes / page_size;
    if (capacity > pipe->capacity) {
        if (capacity * page_size > unprivileged_pipe_bytes &&
            !capable(credentials, Capability::sys_resource))
            return -1;
        if (pipe_quota_applies(credentials)) {
            uint64_t reserved = reserved_pages(pipe->owner) - pipe->capacity + capacity;
            if (exceeds_limit(reserved, pipe_user_pages_soft) ||
                exceeds_limit(reserved, pipe_user_pages_hard))
                return -1;
        }
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
        pipe = create_pipe_buffer(task.credentials, error);
        if (!pipe) {
            close_handle(handle);
            discard_reserved_fd(*task.files, fd);
            return -12;
        }
    }
    if (nonblocking && mode == 1 && !pipe->readers) {
        if (!inode->named_pipe)
            destroy_pipe_buffer(*pipe);
        close_handle(handle);
        discard_reserved_fd(*task.files, fd);
        return -6;
    }
    inode->named_pipe = pipe;
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
