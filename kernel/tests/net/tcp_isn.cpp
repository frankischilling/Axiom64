// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/isn.hpp"
#include <cassert>
#include <cstdio>

int main() {
    uint8_t key[32];
    for (unsigned at = 0; at < 32; at++)
        key[at] = at;
    // Independent Python hmac/hashlib.blake2s fixtures over the encoded tuple/domain.
    assert(ax::tcp::initial_sequence(key, 0xc0000201, 0xc6336402, 49152, 80, 0) == 0x9e6bb9bc);
    assert(ax::tcp::initial_sequence(key, 0xc6336402, 0xc0000201, 80, 49152, 0) == 0xc5530b24);
    assert(ax::tcp::initial_sequence(key, 0xc0000201, 0xc6336402, 49152, 80, UINT32_MAX) ==
           0x9e6bb9bb);
    assert(ax::tcp::initial_sequence(key, 0xc0000201, 0xc6336402, 49152, 80,
                                     uint64_t(UINT32_MAX) + 10) == 0x9e6bb9c5);
    key[31] ^= 1;
    assert(ax::tcp::initial_sequence(key, 0xc0000201, 0xc6336402, 49152, 80, 0) != 0x9e6bb9bc);
    std::puts("TCP_ISN_PASS independent_hmac tuple_direction clock_wrap key_change");
}
