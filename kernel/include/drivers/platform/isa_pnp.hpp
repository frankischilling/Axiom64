// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/isa_pnp.hpp
 * @brief   Declares ISA Plug and Play bus discovery.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Returns verified firmware-assigned ports for supported legacy devices.
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
#include <stdint.h>

namespace ax::IsaPnp {
struct Bus {
    void* context;
    uint8_t (*read)(void*, uint16_t);
    void (*write)(void*, uint16_t, uint8_t);
    bool (*delay)(void*, unsigned);
};

struct Ports {
    uint16_t uart = 0;
    uint16_t printer = 0;
    unsigned cards = 0;
    unsigned rejected = 0;
};

// Assign card select numbers without resetting logical-device assignments.
Ports discover(const Bus&);
} // namespace ax::IsaPnp
