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

    bool mapped() const;

    bool matches(const Address& prefix, unsigned bits) const;
};

// Views borrow captured message bytes until the owned output packet is copied.
struct OutputExtensions {
    const uint8_t* hop = nullptr;
    size_t hop_length = 0;
    const uint8_t* destination = nullptr;
    size_t destination_length = 0;
    const uint8_t* before_routing = nullptr;
    size_t before_routing_length = 0;
    const uint8_t* routing = nullptr;
    size_t routing_length = 0;
};

// Validate a complete segment list and TLVs; received quotes may use reduced SRHs.
bool valid_segment_routing(const uint8_t*, size_t, bool reduced);

// Validate a complete type-2 or unreduced type-4 output Routing header.
bool valid_output_routing(const uint8_t*, size_t);

// Validate complete bounded headers and return their combined wire length.
int output_extension_size(const OutputExtensions&);

// Select the first hop from a validated Routing header; preserve the final address.
bool output_extension_destination(const OutputExtensions&, const Address& final, Address& first);

uint8_t output_next_header(uint8_t protocol, const OutputExtensions&);

// Rewrite copied Next Header bytes and replace the first routing address with the
// final destination. A routing header requires final; errors leave output unchanged.
bool encode_output_extensions(uint8_t*, size_t capacity, uint8_t protocol, const OutputExtensions&,
                              const Address* final = nullptr);

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
    uint32_t header_offset = 0, previous_header_offset = 6;
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
    bool fragmented = false;
    const uint8_t* extensions = nullptr;
    size_t extension_length = 0;
};

// Apply the receiver's bounded option-count and cumulative-padding policy
// separately from structural decoding. The default matches Linux's eight
// non-padding options per header and seven consecutive padding bytes.
bool receive_extension_options(const Packet&, unsigned maximum_options = 8);

// No reassembly, authentication or ICMP emission occurs while decoding. The
// receiver still owns destination checks and RFC 4443 error suppression.
Packet decode(const uint8_t*, size_t);

// Writes only the fixed header; invalid capacity/flow labels leave it unchanged.
bool encode(uint8_t*, size_t capacity, const Header&);

// Complemented upper-layer pseudo-header checksum, including an odd last byte.
uint16_t checksum(const Address&, const Address&, uint8_t protocol, const uint8_t*,
                  uint32_t length);
} // namespace ax::ip6
