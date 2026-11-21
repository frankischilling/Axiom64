// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/boot/boot.hpp
 * @brief   Declares boot requests and early initialization interfaces.
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
#include "limine.h"

namespace ax {
extern volatile limine_hhdm_request hhdm_request;
extern volatile limine_memmap_request memmap_request;
extern volatile limine_module_request module_request;
extern volatile limine_framebuffer_request framebuffer_request;
extern volatile limine_executable_cmdline_request cmdline_request;

const uint8_t* firmware_read(uint64_t address, size_t length, void* context);

namespace Acpi {
struct InterruptTopology;
struct DefinitionBlocks;
} // namespace Acpi

bool firmware_discover(uint64_t rsdp, Acpi::InterruptTopology&, Acpi::DefinitionBlocks&);
void firmware_configure_pci_interrupts(uint64_t rsdp, const Acpi::InterruptTopology&,
                                       const Acpi::DefinitionBlocks&);
} // namespace ax
