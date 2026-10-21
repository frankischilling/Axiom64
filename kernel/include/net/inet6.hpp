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

struct Inet6SendControl {
    ip6::Address source;
    unsigned index = 0;
    uint8_t hops = 64, traffic_class = 0;
    bool dont_fragment = false, present = false;
};

// Captured control bytes belong to the caller until parsing or request teardown.
int inet6_capture_control(Task&, uint64_t pointer, uint64_t length, uint8_t*&);
int inet6_parse_send_control(const Inet6Socket*, const Inet6Address&, const uint8_t*, size_t,
                             Inet6SendControl&);
Inet6SendControl inet6_send_defaults(const Inet6Socket*, const Inet6Address&);

struct Inet6Frame {
    Inet6Address source;
    size_t length;
    ip6::Address destination;
    unsigned index = 0;
    uint8_t hops = 0, traffic_class = 0;
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
size_t inet6_receive_control(Task&, Inet6Socket*, const Inet6Frame&, uint64_t address,
                             uint64_t capacity, uint32_t& flags);
Inet6Address inet6_peer(Inet6Socket*);
int inet6_target(Inet6Socket*, Inet6Address&, bool& named,
                 uint32_t imported_length = sizeof(Inet6Address));
size_t inet6_send_prefix(Inet6Socket*);
int inet6_send_admit(Inet6Socket*, const Inet6Address&, size_t length, const uint8_t* prefix,
                     bool named = false, const Inet6SendControl* = nullptr);
unsigned inet6_shutdown(Inet6Socket*);
size_t inet6_available(Inet6Socket*);
int inet6_error(Inet6Socket*, bool clear = false);
void inet6_complete(Inet6Socket*, size_t bytes, int error);
bool inet6_deliver(unsigned index, const ip6::Packet&);
int64_t inet6_send(Inet6Socket*, const Inet6Address&, const void*, size_t, bool named = false,
                   const Inet6SendControl* = nullptr);
int64_t inet6_read(Inet6Socket*, void*, size_t);
int64_t inet6_syscall(Task&, const Frame&);
} // namespace ax
