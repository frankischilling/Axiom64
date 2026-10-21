// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet6.hpp"

namespace ax {
struct Inet6ExtendedError {
    uint32_t number = 0;
    uint8_t origin = 0, type = 0, code = 0, padding = 0;
    uint32_t information = 0, data = 0;
};

static_assert(sizeof(Inet6ExtendedError) == 16);

struct Inet6Error {
    Inet6Address destination, offender;
    Inet6ExtendedError error;
    ip6::Address packet_destination;
    unsigned index = 0;
    uint8_t hops = 0, traffic_class = 0;
    size_t length = 0;
};

inline const uint8_t* inet6_error_bytes(const Inet6Error* error) {
    return reinterpret_cast<const uint8_t*>(error + 1);
}

// Each queued record owns metadata and payload independently of input packets.
bool inet6_queue_error(Inet6Socket*, const Inet6Error&, const void*, size_t);
bool inet6_error_queued(Inet6Socket*);
// Transfers the front record to the caller, including on later user-copy faults.
Inet6Error* inet6_take_error(Inet6Socket*);
void inet6_purge_errors(Inet6Socket*);
void inet6_local_error(Inet6Socket*, const Inet6Address&, uint32_t mtu, const uint8_t* prefix);
} // namespace ax
