// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/nvme.hpp
 * @brief   NVMe namespace block interface.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exposes PCI NVMe discovery, synchronous I/O, flush, and shutdown.
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
constexpr unsigned nvme_controller_slots = 4;
constexpr unsigned nvme_device_slots = 8;

struct NvmeAddress {
    unsigned controller;
    uint32_t nsid;
};

void nvme_init();
const BlockInfo* nvme_info(unsigned slot);
NvmeAddress nvme_address(unsigned slot);
int nvme_transfer(unsigned slot, uint64_t sector, void* data, size_t count, bool write);
int nvme_flush(unsigned slot);
int nvme_shutdown();
} // namespace ax
