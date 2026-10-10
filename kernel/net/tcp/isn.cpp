// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/isn.hpp"
#include "net/ipv4_wire.hpp"
#include "core/random/primitives.hpp"

namespace ax::tcp {
uint32_t initial_sequence(const uint8_t key[32], uint32_t local, uint32_t peer, uint16_t local_port,
                          uint16_t peer_port, uint64_t clock) {
    uint8_t pad[64], inner[32], result[32];
    uint8_t tuple[20] = {'A', '6', '4', 'T', 'C', 'P', 'v', '1'};
    ip4::put32(tuple + 8, local);
    ip4::put32(tuple + 12, peer);
    ip4::put16(tuple + 16, local_port);
    ip4::put16(tuple + 18, peer_port);
    for (unsigned at = 0; at < 64; at++)
        pad[at] = (at < 32 ? key[at] : 0) ^ 0x36;
    random::Blake2s digest;
    digest.update(pad, sizeof(pad));
    digest.update(tuple, sizeof(tuple));
    digest.finish(inner);
    for (unsigned at = 0; at < 64; at++)
        pad[at] = (at < 32 ? key[at] : 0) ^ 0x5c;
    random::Blake2s outer;
    outer.update(pad, sizeof(pad));
    outer.update(inner, sizeof(inner));
    outer.finish(result);
    uint32_t sequence = uint32_t(clock) + ip4::get32(result);
    random::erase(pad, sizeof(pad));
    random::erase(inner, sizeof(inner));
    random::erase(result, sizeof(result));
    return sequence;
}
} // namespace ax::tcp
