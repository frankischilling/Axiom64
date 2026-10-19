// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip6 {
constexpr size_t header_size = 40;
constexpr uint32_t minimum_mtu = 1280;

// Address bytes retain their network order, including partial prefix bytes.
struct Address {
    uint8_t bytes[16]{};

    bool operator==(const Address&) const = default;

    bool unspecified() const;

    bool multicast() const;

    bool loopback() const;

    bool link_local() const;

    bool matches(const Address& prefix, unsigned bits) const;
};

struct Header {
    Address source, destination;
    uint32_t flow_label = 0;
    uint16_t payload_length = 0;
    uint8_t traffic_class = 0, next_header = 59, hop_limit = 64;
};

enum class Input { discard, payload, no_next_header, fragment, parameter_problem };

struct Fragment {
    uint32_t identification = 0;
    uint16_t offset = 0;
    bool more = false;
};

struct Packet {
    Input input = Input::discard;
    Header header;
    // Borrowed only for payload/fragment results, bounded by the IPv6 length.
    const uint8_t* payload = nullptr;
    size_t length = 0;
    Fragment fragment;
    uint32_t size = 0, error_pointer = 0, next_header_offset = 6;
    uint8_t protocol = 59, error_code = 0;
};

// No reassembly, authentication or ICMP emission occurs while decoding. The
// receiver still owns destination checks and RFC 4443 error suppression.
Packet decode(const uint8_t*, size_t);

// Writes only the fixed header; invalid capacity/flow labels leave it unchanged.
bool encode(uint8_t*, size_t capacity, const Header&);

// Complemented upper-layer pseudo-header checksum, including an odd last byte.
uint16_t checksum(const Address&, const Address&, uint8_t protocol, const uint8_t*,
                  uint32_t length);
} // namespace ax::ip6
