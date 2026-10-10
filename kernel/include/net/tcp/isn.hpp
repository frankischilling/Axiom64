// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>

namespace ax::tcp {
uint32_t initial_sequence(const uint8_t key[32], uint32_t local, uint32_t peer, uint16_t local_port,
                          uint16_t peer_port, uint64_t clock);
}
