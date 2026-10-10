// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::tcp {
constexpr uint8_t fin = 1, syn = 2, rst = 4, psh = 8, ack = 16, urg = 32, ece = 64, cwr = 128;
constexpr size_t maximum_segment_size = 65535 - 20;

// Addresses/ports/numbers are host order; payload borrows the validated IPv4 packet.
struct Segment {
    uint16_t source = 0, destination = 0, window = 0, urgent = 0;
    uint32_t sequence = 0, acknowledgment = 0;
    uint8_t flags = 0;
    uint16_t maximum_segment = 0;
    uint8_t window_scale = 0;
    bool has_window_scale = false;
    const uint8_t* payload = nullptr;
    size_t length = 0;
};

// Malformed/checksum-invalid packets leave output unchanged. Unknown options are skipped.
bool decode(uint32_t source, uint32_t destination, const void*, size_t, Segment&);
// Emit a minimal header, optional SYN MSS, and copied payload; zero means invalid/capacity failure.
size_t encode(uint32_t source, uint32_t destination, const Segment&, void*, size_t capacity);
uint32_t sequence_length(const Segment&);
bool before(uint32_t, uint32_t);
bool acceptable(uint32_t sequence, uint32_t length, uint32_t next, uint32_t window);
enum class Reset { accept, challenge, ignore };
Reset reset(uint32_t sequence, uint32_t next, uint32_t window);
} // namespace ax::tcp
