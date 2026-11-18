// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Handle;
struct Node;
struct Task;
struct Credentials;

struct PipeSlot {
    uint64_t page;
    uint16_t begin, end;
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
        return occupied ? page_size - slot(occupied - 1).end : 0;
    }

    size_t head_bytes() {
        return occupied ? slot(0).end - slot(0).begin : 0;
    }
};

Pipe* create_pipe_buffer(const Credentials&);
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
