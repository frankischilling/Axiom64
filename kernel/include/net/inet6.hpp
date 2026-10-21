// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "net/ipv6/wire.hpp"

namespace ax {
struct Task;
struct Inet6Socket;

struct Inet6Address {
    uint16_t family = 10, port = 0;
    uint32_t flow = 0;
    ip6::Address address;
    uint32_t scope = 0;
};

static_assert(sizeof(Inet6Address) == 28);

struct Inet6Frame {
    Inet6Address source;
    size_t length;
};

inline const uint8_t* inet6_bytes(const Inet6Frame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

void inet6_close(Inet6Socket*);
bool inet6_ready(Inet6Socket*, bool write);
bool inet6_error_queued(Inet6Socket*);
// Synchronous error-queue reads never enter retained blocking I/O.
int64_t inet6_receive_error(Task&, Inet6Socket*, const Frame&);
const Inet6Frame* inet6_front(Inet6Socket*);
void inet6_consume(Inet6Socket*);
Inet6Address inet6_peer(Inet6Socket*);
int inet6_target(Inet6Socket*, Inet6Address&, bool named,
                 uint32_t imported_length = sizeof(Inet6Address));
size_t inet6_send_prefix(Inet6Socket*);
int inet6_send_admit(Inet6Socket*, const Inet6Address&, size_t length, const uint8_t* prefix);
unsigned inet6_shutdown(Inet6Socket*);
size_t inet6_available(Inet6Socket*);
int inet6_error(Inet6Socket*, bool clear = false);
void inet6_complete(Inet6Socket*, size_t bytes, int error);
bool inet6_deliver(unsigned index, const ip6::Packet&);
int64_t inet6_send(Inet6Socket*, const Inet6Address&, const void*, size_t, bool named = false);
int64_t inet6_read(Inet6Socket*, void*, size_t);
int64_t inet6_syscall(Task&, const Frame&);
} // namespace ax
