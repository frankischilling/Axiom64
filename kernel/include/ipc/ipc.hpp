// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
struct Socket {
    bool used, listener, pending, connected, read_closed, write_closed, peer_closed;
    uint16_t type;
    uint8_t local[108];
    size_t local_length;
    Node* bound_node;
    Socket* peer;
    Socket* queue[32];
    size_t queue_head, queue_size, backlog;
    uint8_t* bytes;
    size_t head, size, capacity;
};

struct [[gnu::packed]] EpollEvent {
    uint32_t events;
    uint64_t data;
};

struct EpollItem {
    Handle* handle;
    uint64_t generation;
    int fd;
    EpollEvent event;
    bool used, enabled;
    uint32_t last_ready, pending;
};

struct Epoll {
    EpollItem items[max_fds];
};

int64_t ipc_syscall(Frame*);

void socket_close(Socket*);

bool socket_mount_busy(Mount*);

bool socket_node_busy(Node*);

bool socket_ready(Socket*, bool);

int64_t socket_read(Socket*, void*, size_t, bool peek = false, size_t peek_offset = 0);

int64_t socket_write(Socket*, const void*, size_t);

int64_t socket_accept(Task&, Handle*, uint64_t address, uint64_t length, unsigned flags);

int socket_output_address(Task&, Socket*, uint64_t address, uint64_t length);

uint32_t readiness(Handle*);

bool poll_task_ready(Task&);

int select_events(Task&, const Frame&, bool copy);

void epoll_notify();

void epoll_close(Epoll*);

int64_t shared_memory_syscall(Frame*);

void shared_memory_fork(Task*, const Task*);

void shared_memory_release(Task*);
} // namespace ax
