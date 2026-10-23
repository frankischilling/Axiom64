// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::proc6 {
constexpr unsigned property_count = 8, secret_property = 7;

const char* property_name(unsigned);

// Directory cookies reserve all/default/lo, then one slot per physical index.
const char* scope_name(unsigned cookie);

bool scope_index(const char*, unsigned&);

int64_t read(unsigned index, unsigned property, uint64_t& offset, void*, size_t);

int64_t write(unsigned index, unsigned property, uint64_t& offset, const void*, size_t);
} // namespace ax::proc6
