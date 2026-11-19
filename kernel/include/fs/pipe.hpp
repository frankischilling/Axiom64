// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/pipe.hpp
 * @brief   Pipe queues and quota interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines pipe slots, endpoint lifetime, capacity controls, and the read and
 * write interfaces.
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
#pragma once
#include "core/base.hpp"

namespace ax {
struct Handle;
struct Node;
struct Task;
struct Credentials;

inline constexpr uint32_t pipe_direct = 040000; // Linux O_DIRECT
enum class PipeLimit { max_size, hard_pages, soft_pages };

uint64_t pipe_limit(PipeLimit);
int set_pipe_limit(PipeLimit, uint64_t);

struct PipeSlot {
    uint64_t page;
    uint16_t begin, end;
    bool packet;
};

struct Pipe {
    Pipe* next;
    PipeSlot* slots;
    uint32_t owner;
    unsigned capacity, first, occupied;
    size_t size;
    unsigned readers, writers;
    uint64_t reader_generation, writer_generation;

    bool full() const {
        return occupied == capacity;
    }

    PipeSlot& slot(unsigned index) {
        return slots[(first + index) & (capacity - 1)];
    }

    size_t tail_space() {
        if (!occupied)
            return 0;
        const auto& tail = slot(occupied - 1);
        return tail.packet ? 0 : page_size - tail.end;
    }

    size_t head_bytes() {
        return occupied ? slot(0).end - slot(0).begin : 0;
    }
};

Pipe* create_pipe_buffer(const Credentials&, int& error);
void destroy_pipe_buffer(Pipe&);
int64_t pipe_fcntl(Handle&, unsigned command, uint32_t size, const Credentials&);
int64_t pipe_write(Handle&, const void*, size_t, bool merge_tail);
// Preview queued bytes before committing a userspace copy.
int64_t pipe_read(Pipe*, void*, size_t, bool peek = false);

void attach_pipe(Handle&, Pipe&);
void detach_pipe(Handle&);
int64_t open_fifo(Task&, Node* inode, Node* dentry, uint32_t flags);
bool resume_fifo_open(Task&);
void discard_fifo_open(Task&);
} // namespace ax
