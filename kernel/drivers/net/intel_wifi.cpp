// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi.cpp
 * @brief   Identify the Intel AX201 stepping and stage its firmware sections.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi.hpp"
#include "drivers/platform/fb_console.hpp"
#include "drivers/platform/pci.hpp"
#include "fs/vfs.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr uint32_t device_id = 0x06f08086, subsystem_id = 0x00748086;
constexpr uint32_t wireless_class = 0x028000;
constexpr uint16_t pci_command = 4, memory_space = 2, bus_master = 4, intx_disable = 1u << 10;
constexpr unsigned csr_hw_rev = 0x28, csr_hw_rf_id = 0x9c;
constexpr uint32_t quz_revision = 0x00000351, hr_radio = 0x0010a100;
constexpr char firmware_file[] = "/lib/firmware/iwlwifi-QuZ-a0-hr-b0-77.ucode";
enum class Probe { absent, rejected, identified };
Probe probe;

void report(const char* status) {
    constexpr char prefix[] = "Intel AX201: ";
    for (const char* p = prefix; *p; ++p)
        fb_console_put(*p);
    for (const char* p = status; *p; ++p)
        fb_console_put(*p);
    fb_console_put('\n');
}

bool device_powered(const PciFunction& pci) {
    unsigned end = 0;
    const unsigned pm = pci.find_capability(1, &end);
    return pm && pm + 6 <= end && !(pci.read16(pm + 4) & 3);
}

void probe_adapter(const PciFunction& pci) {
    if (probe == Probe::identified || pci.read32(0) != device_id ||
        pci.read32(0x2c) != subsystem_id || pci.read32(8) >> 8 != wireless_class)
        return;
    probe = Probe::rejected;
    const uint16_t original = pci.read16(pci_command);
    if ((original & bus_master) || !device_powered(pci)) {
        log("iwlwifi: PCI function must be idle in D0\n");
        return;
    }
    PciBar bar{};
    uint64_t address;
    constexpr unsigned bytes = csr_hw_rf_id + sizeof(uint32_t);
    if (pci.probe_bar(0, PciBarSpace::memory, bar) != PciBarStatus::valid ||
        !bar.range(0, bytes, address)) {
        log("iwlwifi: BAR 0 is unavailable\n");
        return;
    }
    auto registers = static_cast<const volatile uint32_t*>(map_mmio(address, bytes));
    if (!registers) {
        log("iwlwifi: cannot map BAR 0\n");
        return;
    }

    // Enable CSR reads without granting DMA. Restore the command word before returning.
    const uint16_t temporary = original | memory_space | intx_disable;
    pci.write16(pci_command, temporary);
    uint32_t revision = UINT32_MAX, radio = UINT32_MAX;
    if (pci.read16(pci_command) == temporary) {
        revision = registers[csr_hw_rev / sizeof(uint32_t)];
        radio = registers[csr_hw_rf_id / sizeof(uint32_t)];
    }
    pci.write16(pci_command, original);
    if (pci.read16(pci_command) != original) {
        log("iwlwifi: cannot restore PCI command word\n");
        return;
    }
    log("iwlwifi: MAC revision=%x radio=%x\n", uint64_t(revision), uint64_t(radio));
    if (revision == quz_revision && radio == hr_radio)
        probe = Probe::identified;
}

struct StagedImage {
    uint64_t addresses[region_count][max_sections]{};
    size_t page_counts[region_count][max_sections]{};

    StagedImage() = default;
    StagedImage(const StagedImage&) = delete;
    StagedImage& operator=(const StagedImage&) = delete;

    ~StagedImage() {
        for (unsigned region = 0; region < region_count; ++region)
            for (unsigned i = 0; i < max_sections; ++i)
                if (addresses[region][i])
                    page_free(addresses[region][i], page_counts[region][i]);
    }

    bool copy(const FirmwareImage& image) {
        for (unsigned region = 0; region < region_count; ++region) {
            const auto& group = image.regions[region];
            for (unsigned i = 0; i < group.count; ++i) {
                const auto& section = group.sections[i];
                const size_t pages = align_up(section.size) / page_size;
                const uint64_t address = Dma::allocate(pages, Dma::pci);
                if (!address)
                    return false;
                page_counts[region][i] = pages;
                addresses[region][i] = address;
                memcpy(physical(address), section.data, section.size);
            }
        }
        return true;
    }

    bool matches(const FirmwareImage& image) const {
        for (unsigned region = 0; region < region_count; ++region) {
            const auto& group = image.regions[region];
            for (unsigned i = 0; i < group.count; ++i) {
                const auto& section = group.sections[i];
                if (memcmp(physical(addresses[region][i]), section.data, section.size))
                    return false;
            }
        }
        return true;
    }
};

void stage_firmware(const uint8_t* bytes, size_t size) {
    FirmwareImage image{};
    if (const auto* error = parse_firmware(bytes, size, image)) {
        log("iwlwifi: firmware rejected: %s\n", error);
        report(error);
        return;
    }
    StagedImage staged;
    if (!staged.copy(image)) {
        log("iwlwifi: DMA staging allocation failed\n");
        report("DMA staging allocation failed");
        return;
    }
    if (!staged.matches(image)) {
        log("iwlwifi: DMA staging readback failed\n");
        report("DMA staging readback failed");
        return;
    }
    log("iwlwifi: DMA staged API=%u LMAC=%u UMAC=%u paging=%u paging_bytes=%u\n",
        uint64_t(image.version[0]), uint64_t(image.regions[lmac].count),
        uint64_t(image.regions[umac].count), uint64_t(image.regions[paging].count),
        uint64_t(image.paging_bytes));
    report("firmware staged in memory");
}
} // namespace

void check_firmware(bool probe_pci) {
    if (probe_pci) {
        probe = Probe::absent;
        pci_scan(probe_adapter);
        if (probe != Probe::identified) {
            const char* status =
                probe == Probe::absent ? "AX201 PCI function absent" : "unsupported PCI function";
            log("iwlwifi: %s\n", status);
            report(status);
            return;
        }
    }
    Node* file = lookup(firmware_file);
    if (!file || (file->mode & 0170000) != regular_file || !file->size ||
        file->size > max_firmware_bytes) {
        log("iwlwifi: firmware missing or invalid: %s\n", firmware_file);
        report("firmware file missing or invalid");
        return;
    }
    const size_t size = file->size;
    auto* bytes = static_cast<uint8_t*>(alloc(size));
    if (!bytes) {
        log("iwlwifi: firmware allocation failed\n");
        report("firmware allocation failed");
        return;
    }
    if (node_read(file, 0, bytes, size) == int64_t(size))
        stage_firmware(bytes, size);
    else {
        log("iwlwifi: firmware read failed\n");
        report("firmware read failed");
    }
    release(bytes);
}
} // namespace ax::IntelWifi
