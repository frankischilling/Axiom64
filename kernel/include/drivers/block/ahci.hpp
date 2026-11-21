// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/ahci.hpp
 * @brief   AHCI SATA disk interface.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Declares discovery, disk geometry, synchronous DMA transfers, and flush.
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
#include "drivers/block/block.hpp"

namespace ax {
constexpr unsigned ahci_device_slots = 8;
constexpr unsigned ahci_transfer_sectors = 32;

void ahci_init();
const BlockInfo* ahci_info(unsigned slot);
int ahci_transfer(unsigned slot, uint64_t sector, void* data, size_t count, bool write);
int ahci_flush(unsigned slot);
} // namespace ax
