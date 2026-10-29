// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::proc {
bool parse_integer(const char*, size_t, bool unsigned_value, int32_t&, size_t& consumed);
int64_t read_integer(int32_t, uint64_t& offset, void*, size_t);
} // namespace ax::proc
