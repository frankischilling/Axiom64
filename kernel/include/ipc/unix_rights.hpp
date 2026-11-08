// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax {
struct Handle;
struct Socket;
struct Task;

// A send captures descriptions, not descriptor numbers. A pending send owns the
// same references while waiting; enqueue makes them part of the receiver graph.
class UnixRights {
    static UnixRights* all;
    static unsigned queued_sockets;
    UnixRights *next = nullptr, *previous = nullptr, *collect_next = nullptr;
    Handle* files[253]{};
    unsigned count = 0, sockets = 0;
    uint32_t uid = 0;
    Socket* receiver = nullptr;
    friend void unix_collect_rights();

  public:
    static constexpr unsigned maximum = 253;
    static UnixRights* create(uint32_t uid);
    void append(Handle*);
    int admission(uint64_t limit, bool privileged) const;
    void enqueue(Socket*);
    void drop();
    size_t write(Task&, uint64_t pointer, size_t capacity, bool cloexec, uint32_t& flags) const;

    unsigned size() const {
        return count;
    }
};

// Called after an outermost description release, when all nested close callbacks
// have finished. References held by pending sends and ordinary descriptors root
// the graph; only unreachable receive queues are cleared.
void unix_collect_rights();
} // namespace ax
