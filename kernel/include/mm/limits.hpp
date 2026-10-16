// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct Task;

bool memory_growth_allowed(const Task&, uint64_t start, size_t length, bool replace = false);

bool data_growth_allowed(const Task&, uint64_t start, size_t length, bool replace = false);

bool memory_protection_allowed(const Task&, uint64_t start, size_t length, int protection);

bool heap_change_allowed(const Task&, uint64_t address);
} // namespace ax
