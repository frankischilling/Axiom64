// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::proc4 {
int64_t source_limit_read(uint64_t& offset, void*, size_t);
int64_t source_limit_write(uint64_t& offset, const void*, size_t);
} // namespace ax::proc4
