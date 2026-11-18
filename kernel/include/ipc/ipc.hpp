// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"
#include "ipc/unix_datagram.hpp"
#include "ipc/unix_stream.hpp"

namespace ax {
struct PeerCredentials {
    int32_t pid = 0;
    uint32_t uid = UINT32_MAX, gid = UINT32_MAX;
};

struct Socket {
    bool used, listener, pending, connected, read_closed, write_closed, peer_closed;
    uint16_t type;
    uint64_t generation, peer_generation;
    Node* bound_node;
    Socket* peer;
    Socket* queue[32];
    size_t queue_head, queue_size, backlog;
    UnixStreamQueue stream{};
    PeerCredentials credentials{}, peer_credentials{};
    UnixDatagramQueue datagrams{};
    // Bindings outlive their endpoint while peer queries or queued bytes own them.
    UnixAddressName* local_name = nullptr;
    UnixAddressName* peer_name = nullptr;
    // Accepted children retain a local name without reserving its namespace entry.
    bool name_registered = false;
    UnixSendBudget* datagram_send = nullptr;
    uint32_t datagram_receive = 212992;
    int datagram_error = 0;
    bool pass_credentials = false;
    Handle* description = nullptr;
    Socket* accepting = nullptr;

    Handle* rights_owner() const {
        return description ? description : accepting ? accepting->description : nullptr;
    }
};

struct UnixDatagramTarget {
    Socket* socket = nullptr;
    uint64_t generation = 0;
};

struct [[gnu::packed]] EpollEvent {
    uint32_t events;
    uint64_t data;
};

struct Epoll;

struct EpollItem {
    Handle* handle;
    uint64_t generation;
    int fd;
    EpollEvent event;
    bool used, enabled;
    uint32_t last_ready, pending;
    uint64_t observed_notification;
    uint64_t signal_wait_queue;
    Epoll* exclusive_owner = nullptr;
    EpollItem* exclusive_prev = nullptr;
    EpollItem* exclusive_next = nullptr;
};

struct Epoll {
    unsigned index, cursor;
    uint64_t notification;
    EpollItem items[max_fds];
};

int64_t ipc_syscall(Frame*);

void socket_close(Socket*);

bool socket_mount_busy(Mount*);

bool socket_node_busy(Node*);

bool socket_ready(Socket*, bool);

int64_t socket_read(Socket*, void*, size_t, bool peek = false, size_t peek_offset = 0);

int64_t socket_write(Socket*, const void*, size_t, uint32_t datagram_entry_limit = 0);
// Success transfers the prepared record to the receiver; errors retain it.
int64_t socket_datagram_write(Task&, Socket*, UnixDatagramRecord*, const UnixAddressValue*,
                              UnixDatagramTarget&);
int socket_unix_address(Task&, uint64_t pointer, uint32_t length, UnixAddressValue&);
int socket_unix_bind(Task&, Socket&, uint64_t pointer, size_t length);
int socket_unix_autobind(Socket&);
int socket_datagram_connect(Task&, Socket&, uint64_t pointer, uint32_t length);
int socket_unix_output_name(Task&, const UnixAddressName*, uint64_t, uint64_t);
bool socket_datagram_writable(const Socket&);

int64_t socket_accept(Task&, Handle*, uint64_t address, uint64_t length, unsigned flags,
                      int reserved_fd);

int socket_output_address(Task&, Socket*, uint64_t address, uint64_t length);

uint32_t readiness(Handle*, const Task*);
const void* readiness_source(const Handle&);

void epoll_notify(Handle* source = nullptr, uint32_t events = 0);
void epoll_signal_notify(const SignalHandlers&);

void epoll_close(Epoll*);
bool epoll_resume_wait(Task&);
void epoll_discard_wait(Task&);
void epoll_stop_wait(Task&);

} // namespace ax
