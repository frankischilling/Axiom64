// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/tcp/wire.hpp"

namespace ax::tcp::detail {
// Family adapters validate pointer, length and checksum before sharing the parser.
bool decode(const void*, size_t, Segment&);
// Encode the transport once; each family adapter then supplies its pseudo-header checksum.
size_t encode(const Segment&, void*, size_t capacity, size_t maximum);
} // namespace ax::tcp::detail
