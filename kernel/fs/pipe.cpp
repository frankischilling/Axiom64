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
#include "io/vectors.hpp"
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
        bool packet = handle.flags & pipe_direct;
        pipe.slot(pipe.occupied++) = {page, 0, 0, packet, !packet};
    }
    auto& slot = pipe.slot(pipe.occupied - 1);
    memcpy(static_cast<uint8_t*>(physical(slot.page)) + slot.end, data, count);
    slot.end += count;
    pipe.size += count;
    epoll_notify(&handle, 1 | 0x40);
    return count;
}

int64_t pipe_transfer(Pipe& input, Pipe& output, size_t length, bool duplicate) {
    if (!input.occupied && input.writers)
        return -11;
    if (!output.readers)
        return -32;
    if (output.full())
        return -11;

    bool input_was_full = input.full();
    size_t moved = 0;
    unsigned index = 0;
    int error = 0;
    while (moved < length && index < input.occupied && !output.full()) {
        auto& source = input.slot(index);
        size_t available = source.end - source.begin;
        size_t count = min(length - moved, available);
        auto target = source;
        if (duplicate || count < available) {
            if (!page_try_retain(source.page)) {
                error = -14;
                break;
            }
            target.can_merge = false;
        }
        target.end = target.begin + count;
        output.slot(output.occupied++) = target;
        output.size += count;
        moved += count;

        if (duplicate) {
            ++index;
        } else {
            input.size -= count;
            if (count == available) {
                input.first = (input.first + 1) & (input.capacity - 1);
                --input.occupied;
            } else {
                source.begin += count;
            }
        }
    }
    if (!moved)
        return error;
    if (input_was_full && !input.full())
        descriptor_wait_notify(&input, 4 | 0x100);
    descriptor_wait_notify(&output, 1 | 0x40);
    return moved;
}

int64_t copy_handle_to_pipe(Handle& input, Pipe& output, size_t length) {
    if (!output.readers)
        return -32;
    if (output.full())
        return -11;
    size_t capacity = min(length, size_t(output.capacity - output.occupied) * page_size);
    if (!capacity)
        return 0;
    size_t pages = (capacity + page_size - 1) / page_size;
    uint64_t page = page_alloc(pages);
    if (!page)
        return -12;
    int64_t received = read_handle(&input, physical(page), capacity);
    size_t used = 0;
    if (received > 0) {
        for (size_t offset = 0; offset < size_t(received); offset += page_size) {
            size_t count = min(size_t(received) - offset, size_t(page_size));
            output.slot(output.occupied++) = {page + offset, 0, uint16_t(count), false, false};
            ++used;
        }
        output.size += received;
        descriptor_wait_notify(&output, 1 | 0x40);
    }
    if (used < pages)
        page_free(page + used * page_size, pages - used);
    return received;
}

int64_t splice_file_to_pipe(Handle& input, Pipe& output, uint64_t& offset, size_t length) {
    if (!output.readers)
        return -32;
    if (output.full())
        return -11;

    size_t moved = 0;
    int64_t result = 0;
    while (moved < length && !output.full()) {
        uint64_t page = page_alloc();
        if (!page) {
            result = -12;
            break;
        }
        size_t count = min(length - moved, size_t(page_size - offset % page_size));
        result = description_read(&input, offset, physical(page), count);
        if (result <= 0) {
            page_free(page);
            break;
        }
        output.slot(output.occupied++) = {page, 0, uint16_t(result), false, false};
        offset += result;
        output.size += result;
        moved += result;
        if (size_t(result) < count)
            break;
    }
    if (moved)
        descriptor_wait_notify(&output, 1 | 0x40);
    return moved ? int64_t(moved) : result;
}

void pipe_consume_head(Pipe& pipe, size_t length) {
    auto& slot = pipe.slot(0);
    bool was_full = pipe.full();
    pipe.size -= length;
    slot.begin += length;
    if (slot.begin == slot.end) {
        page_free(slot.page);
        pipe.first = (pipe.first + 1) & (pipe.capacity - 1);
        --pipe.occupied;
        if (was_full)
            descriptor_wait_notify(&pipe, 4 | 0x100);
    }
}

int64_t splice_pipe_to_device(Pipe& input, Handle& output, size_t length) {
    if (!input.occupied)
        return input.writers ? -11 : 0;
    size_t moved = 0;
    while (moved < length && input.occupied) {
        auto& slot = input.slot(0);
        size_t count = min(length - moved, size_t(slot.end - slot.begin));
        auto bytes = static_cast<const uint8_t*>(physical(slot.page)) + slot.begin;
        auto result = write_handle(&output, bytes, count);
        if (result <= 0)
            return moved ? int64_t(moved) : result;
        pipe_consume_head(input, result);
        moved += result;
        if (size_t(result) < count)
            break;
    }
    return moved;
}

int64_t splice_memory_to_pipe(AddressSpace& space, Pipe& pipe, const IoVector* vectors,
                              size_t count) {
    if (!pipe.readers)
        return -32;
    if (pipe.full())
        return -11;
    size_t moved = 0;
    int error = 0;
    for (size_t i = 0; i < count && !pipe.full() && !error; ++i) {
        const auto& vector = vectors[i];
        for (size_t at = 0; at < vector.length && !pipe.full();) {
            uint64_t address = vector.base + at;
            uint16_t begin = address % page_size;
            size_t length = min(size_t(vector.length - at), size_t(page_size - begin));
            uint64_t page = space.retain_readable_page(address);
            if (!page) {
                error = -14;
                break;
            }
            pipe.slot(pipe.occupied++) = {page, begin, uint16_t(begin + length), false, false};
            pipe.size += length;
            moved += length;
            at += length;
        }
    }
    if (moved)
        descriptor_wait_notify(&pipe, 1 | 0x40);
    return moved ? int64_t(moved) : error;
}

int64_t splice_pipe_to_file(Task& task, Pipe& input, Handle& output, uint64_t& offset,
                            size_t length) {
    if (!input.occupied)
        return input.writers ? -11 : 0;
    size_t moved = 0;
    int64_t result = 0;
    while (moved < length && input.occupied) {
        auto& slot = input.slot(0);
        size_t available = slot.end - slot.begin;
        size_t count = min(length - moved, available);
        if (int error = write_handle_limit_at(&task, output, offset, count)) {
            result = error;
            break;
        }
        auto bytes = static_cast<const uint8_t*>(physical(slot.page)) + slot.begin;
        uint64_t before = offset;
        result = write_regular_at(&task, output, offset, bytes, count);
        size_t committed = offset - before;
        moved += committed;
        if (committed)
            pipe_consume_head(input, committed);
        if (result <= 0)
            break;
    }
    return moved ? int64_t(moved) : result;
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
