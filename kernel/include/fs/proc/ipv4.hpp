// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::proc4 {
constexpr unsigned property_count = 2, forwarding_property = 1;
const char* property_name(unsigned);
const char* scope_name(unsigned cookie);
bool scope_index(const char*, unsigned&);
uint64_t scope_generation(unsigned);
int64_t read(unsigned index, unsigned property, uint64_t& offset, void*, size_t);
int64_t write(unsigned index, unsigned property, uint64_t& offset, const void*, size_t);

int64_t source_limit_read(uint64_t& offset, void*, size_t);
int64_t source_limit_write(uint64_t& offset, const void*, size_t);
} // namespace ax::proc4
