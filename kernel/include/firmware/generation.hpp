// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/firmware/generation.hpp
 * @brief   Firmware environment detection.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines firmware generation values and exposes boot firmware detection.
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

namespace ax::Firmware {
using Read = bool (*)(void*, uint16_t, size_t, void*, size_t);

// QEMU's fw_cfg generation file is supplied by the current hypervisor instance,
// rather than restored from a guest memory snapshot. Identifiers are not entropy.
class Generation {
    Read reader = nullptr;
    void* context = nullptr;
    uint16_t selector = 0;
    uint32_t slot = 0;
    uint8_t previous[16]{};
    bool live = false;

    bool discover();

    bool identifier(uint8_t[16]);

  public:
    bool initialize(Read, void*, uint8_t[16]);

    // Returns 1 for a changed identifier, 0 for unchanged/absent, -1 on failure.
    int poll(uint8_t[16]);

    bool active() const {
        return live;
    }
};
} // namespace ax::Firmware
