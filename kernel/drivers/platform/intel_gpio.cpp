// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/intel_gpio.cpp
 * @brief   Reads Intel GPIO pad configuration for ACPI replay.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Bounds register reads to the pad ranges in the firmware resource map.
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
#include "drivers/platform/intel_gpio.hpp"
#include "core/base.hpp"

namespace ax {
namespace {
constexpr unsigned register_window_size = 0x10000;
constexpr unsigned padbar_offset = 0x0c, pad_stride = 16;
constexpr unsigned pad_min_offset = 0x100;
constexpr unsigned pad_cfg_bytes = 8; // PADCFG DW0 and DW1.
} // namespace

bool IntelGpioPads::probe(const Acpi::IntelGpioResources& resources) {
    using Model = Acpi::IntelGpioResources::Model;
    constexpr unsigned lp_pad_counts[]{68, 113, 63};
    constexpr unsigned h_pad_counts[]{51, 104, 94, 50};
    if (resources.model == Model::none)
        return false;
    const bool low_power = resources.model == Model::cannon_lake_lp;
    const unsigned* counts = low_power ? lp_pad_counts : h_pad_counts;
    const unsigned count = low_power ? 3 : 4;

    Community detected[4]{};
    memset(communities, 0, sizeof(communities));
    for (unsigned i = 0; i < count; ++i) {
        const uint64_t base = resources.community_base[i];
        const auto* regs = static_cast<volatile uint32_t*>(map_mmio(base, register_window_size));
        if (!regs)
            return false;
        const uint32_t revision = regs[0];
        const uint32_t padbar = regs[padbar_offset / 4];
        if (revision == UINT32_MAX || (revision >> 16) < 0x92 || padbar < pad_min_offset ||
            padbar % pad_stride || padbar > register_window_size - counts[i] * pad_stride)
            return false;
        detected[i] = {base, regs, padbar, counts[i]};
    }
    memcpy(communities, detected, sizeof(communities));
    return true;
}

bool IntelGpioPads::read(void* context, uint64_t address, uint8_t* bytes, size_t length) {
    if (!context || !bytes || !length || length > sizeof(uint32_t) - (address & 3))
        return false;
    const auto& pads = *static_cast<const IntelGpioPads*>(context);
    for (const auto& community : pads.communities) {
        if (!community.regs || address < community.base)
            continue;
        const uint64_t offset = address - community.base;
        if (offset < community.first_pad_offset)
            continue;
        const uint64_t pad_offset = offset - community.first_pad_offset;
        if (pad_offset / pad_stride >= community.pad_count ||
            pad_offset % pad_stride >= pad_cfg_bytes)
            continue;
        const uint32_t word = community.regs[offset / 4];
        if (word == UINT32_MAX)
            return false;
        for (size_t i = 0; i < length; ++i)
            bytes[i] = uint8_t(word >> (8 * ((offset & 3) + i)));
        return true;
    }
    return false;
}

bool intel_gpio_firmware_interface(const uint8_t* name, size_t length) {
    // Firmware uses this interface query to return the I2C resources alongside the interrupt.
    constexpr char gpio_aware[] = "Windows 2015";
    return length == sizeof(gpio_aware) - 1 && !memcmp(name, gpio_aware, length);
}
} // namespace ax
