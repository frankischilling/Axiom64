// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/power.cpp
 * @brief   Platform power control.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Handles the supported machine shutdown operation invoked by the kernel.
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
#include "drivers/platform/power.hpp"
#include "drivers/platform/pci.hpp"

namespace ax {
static uint16_t pm_base;

static void find_power_management(const PciFunction& device) {
    if (!pm_base && device.read32(0) == 0x71138086 && (device.read8(0x80) & 1))
        pm_base = device.read32(0x40) & 0xffc0;
}

void platform_poweroff() {
    pm_base = 0;
    pci_scan(find_power_management);
    if (!pm_base) {
        log("PLATFORM_POWEROFF_UNAVAILABLE\n");
        return;
    }
    // QEMU's pc PIIX4 uses sleep type zero for soft power off. General ACPI
    // platforms require FADT and AML discovery before selecting their S5 type.
    uint16_t control = pm_base + 4;
    log("PLATFORM_POWEROFF method=piix4\n");
    out16(control, (in16(control) & ~0x1c00) | 0x2000);
}
} // namespace ax
