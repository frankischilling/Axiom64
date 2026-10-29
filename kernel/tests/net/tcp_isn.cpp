// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/isn.hpp"
#include "net/ipv6/wire.hpp"
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
    ax::ip6::Address local{{0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                            0x11, 0x22, 0x33, 0x44}};
    ax::ip6::Address peer{{0x20, 0x01, 0x0d, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                           0xaa, 0xbb, 0xcc, 0xdd}};
    constexpr uint32_t ipv6 = 0x6cda3571;
    assert(ax::tcp::initial_sequence(key, local, peer, 49152, 443, 0) == ipv6);
    assert(ax::tcp::initial_sequence(key, peer, local, 443, 49152, 0) == 0xb2e361a6);
    assert(ax::tcp::initial_sequence(key, local, peer, 49152, 443, UINT32_MAX) == ipv6 - 1);
    assert(ax::tcp::initial_sequence(key, local, peer, 49152, 443, uint64_t(UINT32_MAX) + 10) ==
           ipv6 + 9);
    for (unsigned side = 0; side < 2; side++)
        for (unsigned at = 0; at < 16; at++) {
            auto a = local, b = peer;
            (side ? b : a).bytes[at] ^= 1;
            assert(ax::tcp::initial_sequence(key, a, b, 49152, 443, 0) != ipv6);
        }
    assert(ax::tcp::initial_sequence(key, local, peer, 49153, 443, 0) != ipv6);
    assert(ax::tcp::initial_sequence(key, local, peer, 49152, 444, 0) != ipv6);
    ax::ip6::Address mapped_local{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}};
    ax::ip6::Address mapped_peer{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 2}};
    assert(ax::tcp::initial_sequence(key, mapped_local, mapped_peer, 49152, 80, 0) != 0x9e6bb9bc);
    key[31] ^= 1;
    assert(ax::tcp::initial_sequence(key, local, peer, 49152, 443, 0) != ipv6);
    assert(ax::tcp::initial_sequence(key, 0xc0000201, 0xc6336402, 49152, 80, 0) != 0x9e6bb9bc);
    std::puts("TCP_ISN_PASS independent_hmac ipv4 ipv6 full_addresses domains ports "
              "tuple_direction clock_wrap key_change");
}
