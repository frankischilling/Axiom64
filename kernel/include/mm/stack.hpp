// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct AddressSpace;

// Resolve only the current task's anonymous grow-down stack mappings.
bool grow_user_stack(const AddressSpace&, uint64_t address, size_t length, bool write,
                     bool execute = false);

// Normalize Linux mprotect flags and extend a grow-down request within its mapping.
int memory_protection_range(const AddressSpace&, uint64_t& address, uint64_t& length,
                            uint64_t& protection);
} // namespace ax
