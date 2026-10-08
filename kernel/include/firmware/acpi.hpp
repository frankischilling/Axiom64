// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax::Acpi {
constexpr size_t max_table_bytes = 65536;
constexpr size_t max_root_entries = 256;
using Read = const uint8_t* (*)(uint64_t physical_address, size_t length, void* context);

struct Hpet {
    uint64_t address = 0;
    uint32_t id = 0;
};

// Reader must return stable, mapped bytes or nullptr. Never follows unbounded lengths.
bool find_hpet(uint64_t rsdp, Read reader, void* context, Hpet& result);
} // namespace ax::Acpi
