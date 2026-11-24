// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/intel_gpio.hpp
 * @brief   Declares the Intel LPSS I²C boot probe.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Checks PCI power and the memory aperture before I²C controller discovery.
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
#include "firmware/aml.hpp"

namespace ax {

class IntelGpioPads {
    struct Community {
        uint64_t base;
        const volatile uint32_t* regs;
        unsigned first_pad_offset;
        unsigned pad_count;
    };

    Community communities[4]{};

  public:
    bool probe(const Acpi::IntelGpioResources&);
    static bool read(void* context, uint64_t address, uint8_t* bytes, size_t length);
};

// Select the firmware's GPIO-aware resource layout during the private replay.
bool intel_gpio_firmware_interface(const uint8_t*, size_t);
} // namespace ax
