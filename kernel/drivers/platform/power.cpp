// SPDX-License-Identifier: GPL-3.0-or-later
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
