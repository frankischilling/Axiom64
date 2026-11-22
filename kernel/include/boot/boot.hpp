// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/boot/boot.hpp
 * @brief   Declares normalized boot data and early initialization interfaces.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Connects bootloader responses to the memory, firmware, clock, root
 * filesystem, and userspace startup paths.
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
#pragma once
#include "core/base.hpp"

namespace ax {
enum class BootMemoryKind { usable, reserved, firmware, retained, mapped_reserved, other };

struct BootMemory {
    uint64_t base, length;
    BootMemoryKind kind;
};

struct BootFramebuffer {
    void* address;
    uint64_t width, height, pitch;
    uint16_t bpp;
    uint8_t red_mask_size, red_mask_shift, green_mask_size, green_mask_shift, blue_mask_size,
        blue_mask_shift;
};

struct BootInfo {
    const char* protocol;
    const char* firmware;
    const char* command;
    uint64_t direct_offset, rsdp;
    const void* memory_context;
    size_t memory_count;
    BootMemory (*memory_at)(const void*, size_t);
    const void* initramfs;
    uint64_t initramfs_size, module_count;
    BootFramebuffer framebuffer;
};

extern BootInfo boot_info;
[[noreturn]] void boot_kernel();
void boot_probe_application_processors();

const uint8_t* firmware_read(uint64_t address, size_t length, void* context);

namespace Acpi {
struct InterruptTopology;
struct DefinitionBlocks;
} // namespace Acpi

bool firmware_discover(uint64_t rsdp, Acpi::InterruptTopology&, Acpi::DefinitionBlocks&);
void firmware_configure_pci_interrupts(uint64_t rsdp, const Acpi::InterruptTopology&,
                                       const Acpi::DefinitionBlocks&);
} // namespace ax
