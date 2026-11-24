// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi.cpp
 * @brief   Identify the Intel AX201 stepping and stage its firmware sections.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "core/time.hpp"
#include "drivers/net/intel_wifi_start.hpp"
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
constexpr uint32_t hr_radio = 0x0010a100;
constexpr char firmware_file[] = "/lib/firmware/iwlwifi-QuZ-a0-hr-b0-77.ucode";
enum class Probe { absent, rejected, identified };
Probe probe;
PciFunction adapter{};
volatile uint32_t* adapter_registers;
bool start_requested;
PassiveScan completed_scan{};

void report(const char* status) {
    constexpr char prefix[] = "Intel AX201: ";
    for (const char* p = prefix; *p; ++p)
        fb_console_put(*p);
    for (const char* p = status; *p; ++p)
        fb_console_put(*p);
    fb_console_put('\n');
}

void log_access_point(const AccessPoint& point) {
    constexpr char hex[] = "0123456789abcdef";
    char ssid[sizeof(point.ssid) * 4 + 1];
    unsigned length = 0;
    for (unsigned i = 0; i < point.ssid_length; ++i) {
        const auto byte = point.ssid[i];
        if (byte >= ' ' && byte <= '~' && byte != '"' && byte != '\\') {
            ssid[length++] = char(byte);
        } else {
            ssid[length++] = '\\';
            ssid[length++] = 'x';
            ssid[length++] = hex[byte >> 4];
            ssid[length++] = hex[byte & 0xf];
        }
    }
    ssid[length] = '\0';
    char bssid[18];
    for (unsigned i = 0; i < sizeof(point.bssid); ++i) {
        const auto byte = point.bssid[i];
        bssid[i * 3] = hex[byte >> 4];
        bssid[i * 3 + 1] = hex[byte & 0xf];
        bssid[i * 3 + 2] = i == 5 ? '\0' : ':';
    }
    log("iwlwifi: BSS %s at %u MHz signal_dbm=%d interval_tu=%u capability=%x source=%s "
        "beacon_ies=%u probe_ies=%u ssid=\"%s\"\n",
        bssid, uint64_t(point.frequency_mhz), int64_t(point.signal_dbm),
        uint64_t(point.beacon_interval_tu), uint64_t(point.capability),
        point.probe_response ? "probe" : "beacon", uint64_t(point.beacon_ie_bytes),
        uint64_t(point.probe_ie_bytes), ssid);
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
    const unsigned bytes = (start_requested ? 0x1c80 : csr_hw_rf_id) + sizeof(uint32_t);
    if (pci.probe_bar(0, PciBarSpace::memory, bar) != PciBarStatus::valid ||
        !bar.range(0, bytes, address)) {
        log("iwlwifi: BAR 0 is unavailable\n");
        return;
    }
    auto registers = static_cast<volatile uint32_t*>(map_mmio(address, bytes));
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
    if (revision == quz_mac_revision && radio == hr_radio) {
        adapter = pci;
        adapter_registers = registers;
        probe = Probe::identified;
    }
}

struct StagedImage {
    FirmwareAddresses addresses{};
    size_t page_counts[region_count][max_sections]{};
    bool retain = false;

    StagedImage() = default;
    StagedImage(const StagedImage&) = delete;
    StagedImage& operator=(const StagedImage&) = delete;

    ~StagedImage() {
        if (retain)
            return;
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

struct DmaBuffer {
    uint64_t address = 0;
    size_t pages = 0;
    bool retain = false;

    DmaBuffer() = default;
    DmaBuffer(const DmaBuffer&) = delete;
    DmaBuffer& operator=(const DmaBuffer&) = delete;

    ~DmaBuffer() {
        if (address && !retain)
            page_free(address, pages);
    }

    bool allocate(size_t bytes) {
        pages = align_up(bytes) / page_size;
        address = Dma::allocate(pages, Dma::pci);
        return address != 0;
    }

    template <typename T> T& data() const {
        return *static_cast<T*>(physical(address));
    }
};

struct BootQueues {
    using FreeRing = uint64_t[rx_ring_entries];
    using Commands = CommandDescriptor[command_ring_entries];
    using InvalidCommand = uint8_t[invalid_command_size];
    using UsedRing = uint32_t[rx_ring_entries];

    DmaBuffer free_ring, used_ring, status, commands, invalid_command, context;
    DmaBuffer command_payloads;
    unsigned receive_count = 0;

    void pin_until_reboot() {
        DmaBuffer* buffers[] = {&free_ring,       &used_ring, &status,          &commands,
                                &invalid_command, &context,   &command_payloads};
        for (auto* buffer : buffers)
            buffer->retain = true;
    }

    ~BootQueues() {
        if (free_ring.retain)
            return;
        for (unsigned i = 0; i < receive_count; ++i)
            page_free(align_down(free_ring.data<FreeRing>()[i]), 1);
    }

    bool prepare(const FirmwareImage& image, const FirmwareAddresses& addresses) {
        if (!free_ring.allocate(sizeof(FreeRing)) || !used_ring.allocate(sizeof(UsedRing)) ||
            !status.allocate(sizeof(ReceiveStatus)) || !commands.allocate(sizeof(Commands)) ||
            !invalid_command.allocate(sizeof(InvalidCommand)) ||
            !context.allocate(sizeof(BootContext)))
            return false;

        if (!prepare_command_ring(invalid_command.address, invalid_command.data<InvalidCommand>(),
                                  commands.data<Commands>()) ||
            !make_boot_context(image, addresses,
                               {free_ring.address, used_ring.address, status.address},
                               commands.address, context.data<BootContext>()))
            return false;

        // Keep one slot empty. The hardware write pointer is programmed after it configures RX.
        auto& ring = free_ring.data<FreeRing>();
        for (; receive_count < rx_ring_entries - 1; ++receive_count) {
            const auto address = Dma::allocate(1, Dma::pci);
            if (!address)
                return false;
            if (!encode_receive_buffer(address, receive_count + 1, ring[receive_count])) {
                page_free(address, 1);
                return false;
            }
        }
        return true;
    }
};

bool interrupts_inactive(const PciFunction& pci) {
    unsigned limit = 0;
    unsigned capability = pci.find_capability(5, &limit);
    if (capability && (capability + 4 > limit || (pci.read16(capability + 2) & 1)))
        return false;
    capability = pci.find_capability(0x11, &limit);
    return !capability || (capability + 4 <= limit && !(pci.read16(capability + 2) & (1u << 15)));
}

struct AdapterBoot {
    uint16_t command;
    const BootQueues& queues;
};

void launch_firmware(BootQueues& queues, StagedImage& staged, FirmwareCheck check,
                     const AntennaMasks& antennas) {
    const bool nvm = check >= FirmwareCheck::nvm;
    if (nvm && !queues.command_payloads.allocate(sizeof(CommandPayloads))) {
        report("command buffer allocation failed");
        return;
    }
    const auto original = adapter.read16(pci_command);
    if ((original & bus_master) || !device_powered(adapter) || !interrupts_inactive(adapter)) {
        report("PCI function is not idle for startup");
        return;
    }
    ScanElementStorage* elements = nullptr;
    if (check == FirmwareCheck::passive_scan) {
        elements = static_cast<ScanElementStorage*>(alloc(sizeof(ScanElementStorage)));
        if (!elements) {
            report("scan result allocation failed");
            return;
        }
    }
    AdapterBoot boot{uint16_t(original | memory_space | intx_disable), queues};
    adapter.write16(pci_command, boot.command);
    if (adapter.read16(pci_command) != boot.command) {
        adapter.write16(pci_command, original);
        report("cannot enable PCI register access");
        release(elements);
        return;
    }

    const FirmwareBootIo io{
        &boot,
        [](void*, unsigned offset) { return adapter_registers[offset / sizeof(uint32_t)]; },
        [](void*, unsigned offset, uint32_t value) {
            adapter_registers[offset / sizeof(uint32_t)] = value;
        },
        [](void*, unsigned usec) { return clock_delay_us(usec); },
        [](void* state, bool enable) {
            const auto& boot = *static_cast<AdapterBoot*>(state);
            const auto command = uint16_t(boot.command | (enable ? bus_master : 0));
            adapter.write16(pci_command, command);
            return adapter.read16(pci_command) == command;
        },
        [](void* state, unsigned id) -> const uint8_t* {
            const auto& queues = static_cast<AdapterBoot*>(state)->queues;
            if (!id || id > queues.receive_count)
                return nullptr;
            return static_cast<const uint8_t*>(
                physical(align_down(queues.free_ring.data<BootQueues::FreeRing>()[id - 1])));
        },
    };
    FirmwareBootMemory memory{queues.context.address, &queues.status.data<ReceiveStatus>(),
                              queues.used_ring.data<BootQueues::UsedRing>()};
    if (nvm) {
        memory.commands = queues.commands.data<BootQueues::Commands>();
        memory.command_payloads = &queues.command_payloads.data<CommandPayloads>();
        memory.command_dma = queues.command_payloads.address;
    }
    const ScanChecks scan{antennas, check, elements};
    const auto result =
        start_and_stop_quz(io, memory, check >= FirmwareCheck::scan_config ? &scan : nullptr);
    const auto restore = result.dma_idle ? original : uint16_t(original | intx_disable);
    adapter.write16(pci_command, restore);
    const bool restored = adapter.read16(pci_command) == restore;
    log("iwlwifi: %s, DMA idle=%u, PCI command restored=%u\n", result.status,
        uint64_t(result.dma_idle), uint64_t(restored));
    report(result.status);
    if (result.nvm.version)
        log("iwlwifi: NVM version=%x channels=%u bands=%x TX=%x RX=%x\n",
            uint64_t(result.nvm.version), uint64_t(result.nvm.channel_count),
            uint64_t(result.nvm.bands), uint64_t(result.nvm.tx_chains),
            uint64_t(result.nvm.rx_chains));
    if (result.regulatory.country[0])
        log("iwlwifi: regulatory domain=%s permitted=%u slots=%u\n", result.regulatory.country,
            uint64_t(result.regulatory.valid_channels), uint64_t(result.regulatory.channel_slots));
    if (result.successful && result.dma_idle && restored &&
        result.passive.status == PassiveScan::Status::complete) {
        release(completed_scan.elements);
        completed_scan = result.passive;
        elements = nullptr;
        const auto& passive = *passive_scan_snapshot();
        log("iwlwifi: passive scan channels=%u access points=%u truncated=%u\n",
            uint64_t(passive.channel_count), uint64_t(passive.access_point_count),
            uint64_t(passive.access_points_truncated));
        for (unsigned i = 0; i < passive.access_point_count; ++i)
            log_access_point(passive.access_points[i]);
        if (passive.access_points_truncated) {
            report("at least 32 access points seen");
        } else {
            char count[] = "access points seen: 00";
            count[sizeof(count) - 3] = char('0' + passive.access_point_count / 10);
            count[sizeof(count) - 2] = char('0' + passive.access_point_count % 10);
            report(count);
        }
    }
    release(elements);
    if (!result.dma_idle || !restored) {
        queues.pin_until_reboot();
        staged.retain = true;
        report("DMA buffers reserved until reboot");
    } else if (result.alive) {
        report("adapter reset and stopped");
    }
}

void stage_firmware(const uint8_t* bytes, size_t size, FirmwareCheck check) {
    FirmwareImage image{};
    if (const auto* error = parse_firmware(bytes, size, image)) {
        log("iwlwifi: firmware rejected: %s\n", error);
        report(error);
        return;
    }
    if (check >= FirmwareCheck::nvm && image.nvm_version != 4) {
        log("iwlwifi: unsupported NVM version %u\n", uint64_t(image.nvm_version));
        report("firmware does not advertise NVM version 4");
        return;
    }
    if (check != FirmwareCheck::stage && image.alive_version != 6) {
        log("iwlwifi: unsupported ALIVE version %u\n", uint64_t(image.alive_version));
        report("firmware does not advertise ALIVE version 6");
        return;
    }
    if (check >= FirmwareCheck::scan_config &&
        (image.scan_config_version != 5 || !image.antennas.tx || !image.antennas.rx)) {
        report("firmware lacks scan configuration v5 or antenna masks");
        return;
    }
    if (check >= FirmwareCheck::regulatory && !image.current_regulatory_profile) {
        report("firmware lacks a supported regulatory profile query");
        return;
    }
    if (check == FirmwareCheck::passive_scan && !image.passive_scan_supported) {
        report("firmware lacks the supported passive scan commands");
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
    BootQueues queues;
    if (!queues.prepare(image, staged.addresses)) {
        log("iwlwifi: boot context preparation failed\n");
        report("boot context preparation failed");
        return;
    }
    const auto& context = queues.context.data<BootContext>();
    log("iwlwifi: boot context dwords=%u RX=%u buffers=%u commands=%u\n", uint64_t(context.dwords),
        uint64_t(rx_ring_entries), uint64_t(queues.receive_count), uint64_t(command_ring_entries));
    log("iwlwifi: DMA staged API=%u LMAC=%u UMAC=%u paging=%u paging_bytes=%u\n",
        uint64_t(image.version[0]), uint64_t(image.regions[lmac].count),
        uint64_t(image.regions[umac].count), uint64_t(image.regions[paging].count),
        uint64_t(image.paging_bytes));
    report("firmware and boot queues staged in memory");
    if (check != FirmwareCheck::stage)
        launch_firmware(queues, staged, check, image.antennas);
}
} // namespace

const PassiveScan* passive_scan_snapshot() {
    return completed_scan.status == PassiveScan::Status::complete ? &completed_scan : nullptr;
}

void check_firmware(bool probe_pci, FirmwareCheck check) {
    const bool start = check != FirmwareCheck::stage;
    if (probe_pci || start) {
        start_requested = start;
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
        stage_firmware(bytes, size, check);
    else {
        log("iwlwifi: firmware read failed\n");
        report("firmware read failed");
    }
    release(bytes);
}
} // namespace ax::IntelWifi
