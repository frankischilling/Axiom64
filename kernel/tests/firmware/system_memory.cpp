// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/firmware/system_memory.cpp
 * @brief   Check firmware SystemMemory access and global lock ownership.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "boot/boot.hpp"

#include <array>
#include <cassert>
#include <cstdio>

namespace {
constexpr uint64_t rsdp = 0x1000, xsdt = 0x1100, fadt = 0x1200, facs = 0x2000, config = 0x3000;
alignas(64) std::array<uint8_t, 0x4000> memory{};
ax::BootMemory entries[] = {
    {rsdp, 4096, ax::BootMemoryKind::firmware},
    {facs, 4096, ax::BootMemoryKind::acpi_nvs},
    {config, 4096, ax::BootMemoryKind::reserved},
    {config + 1, 1, ax::BootMemoryKind::acpi_nvs},
};
unsigned mappings;

ax::BootMemory entry(const void*, size_t index) {
    return entries[index];
}

void put(uint64_t addr, uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        memory[addr + i] = uint8_t(value >> (i * 8));
}

void checksum(uint64_t address, unsigned length, unsigned index) {
    uint8_t sum = 0;
    for (unsigned i = 0; i < length; ++i)
        sum += memory[address + i];
    memory[address + index] = uint8_t(-sum);
}

void setup() {
    ax::boot_info.rsdp = rsdp;
    ax::boot_info.memory_at = entry;
    ax::boot_info.memory_count = 3;
    memcpy(&memory[rsdp], "RSD PTR ", 8);
    memory[rsdp + 15] = 2;
    put(rsdp + 20, 36, 4);
    put(rsdp + 24, xsdt, 8);
    checksum(rsdp, 20, 8);
    checksum(rsdp, 36, 32);
    memcpy(&memory[xsdt], "XSDT", 4);
    put(xsdt + 4, 44, 4);
    put(xsdt + 36, fadt, 8);
    checksum(xsdt, 44, 9);
    memcpy(&memory[fadt], "FACP", 4);
    put(fadt + 4, 116, 4);
    memory[fadt + 8] = 6;
    put(fadt + 36, facs, 4);
    put(fadt + 64, 0x1804, 4);
    memory[fadt + 89] = 2;
    checksum(fadt, 116, 9);
    memcpy(&memory[facs], "FACS", 4);
    put(facs + 4, 64, 4);
    memory[config] = 0x42;
    memory[config + 1] = 0x24;
}
} // namespace

namespace ax {
BootInfo boot_info{};
uint64_t direct_map;

void* map_mmio(uint64_t address, size_t length) {
    ++mappings;
    assert(address < memory.size() && length <= memory.size() - address);
    return &memory[address];
}
} // namespace ax

int main(int argc, char** argv) {
    using namespace ax;
    setup();
    uint8_t result[2]{};
    if (argc == 2) {
        assert(!strcmp(argv[1], "--reserved-facs"));
        entries[1].kind = BootMemoryKind::reserved;
        assert(!firmware_read_system_memory(config, result, 2, true) && !result[0]);
        assert(firmware_read_system_memory(config, result, 2, false) && result[0] == 0x42);
        std::puts("ACPI_SYSTEM_MEMORY_FACS_REJECT_PASS");
        return 0;
    }
    assert(firmware_read_system_memory(config, result, 2, false));
    assert(result[0] == 0x42 && result[1] == 0x24);
    assert(firmware_read_system_memory(config, result, 2, true));
    assert(result[0] == 0x42 && memory[facs + 16] == 0);
    put(facs + 16, 2, 4);
    result[0] = 0;
    assert(!firmware_read_system_memory(config, result, 2, true) && !result[0]);
    assert(memory[facs + 16] == 2);
    boot_info.memory_count = 4;
    const unsigned before = mappings;
    assert(!firmware_read_system_memory(config, result, 2, false));
    assert(!firmware_read_system_memory(config + 4095, result, 2, false));
    assert(!firmware_read_system_memory(fadt, result, 2, false));
    assert(!firmware_read_system_memory(UINT64_MAX - 1, result, 2, false));
    assert(mappings == before);
    boot_info.memory_count = 3;
    entries[2].kind = BootMemoryKind::usable;
    assert(!firmware_read_system_memory(config, result, 2, false));
    entries[2].kind = BootMemoryKind::acpi_nvs;
    assert(firmware_read_system_memory(config, result, 2, false) && result[0] == 0x42);
    std::puts("ACPI_SYSTEM_MEMORY_PASS");
}
