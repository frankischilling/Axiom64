// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>

namespace ax::ip6 {
struct Address;
}

namespace ax::tcp {
uint32_t initial_sequence(const uint8_t key[32], uint32_t local, uint32_t peer, uint16_t local_port,
                          uint16_t peer_port, uint64_t clock);
// Hash every network-order IPv6 address byte in a separate tuple domain.
// IPv4-mapped streams use their IPv4 wire tuple and the IPv4 overload.
uint32_t initial_sequence(const uint8_t key[32], const ip6::Address& local,
                          const ip6::Address& peer, uint16_t local_port, uint16_t peer_port,
                          uint64_t clock);
} // namespace ax::tcp
