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
#include "drivers/net/intel_wifi_live.hpp"
#include "drivers/platform/fb_console.hpp"
#include "drivers/platform/pci.hpp"
#include "fs/vfs.hpp"
#include "mm/dma.hpp"
#include "net/ethernet.hpp"
#include "net/netlink_wireless.hpp"
#include <new>

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
ScanChannelList radio_channels{};
uint32_t completed_generation = 1;
void poll_runtime(NetAdapter&);
void stop_runtime(NetAdapter&);
NetAdapter scanned_adapter{
    .info{.live = true, .stats{}, .wireless = true},
    .poll = poll_runtime,
    .send = [](NetAdapter&, const void*, size_t) { return -95; },
    .stop = stop_runtime,
    .data = nullptr,
    .receive_only_diagnostic = true,
};

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
    using ReceiveDescriptors = uint64_t[rx_ring_entries - 1];
    using ManagementDescriptors = CommandDescriptor[management_queue_entries];

    DmaBuffer free_ring, used_ring, status, commands, invalid_command, context;
    DmaBuffer command_payloads, receive_map;
    DmaBuffer management_ring, management_byte_counts;
    DmaBuffer data_ring, data_byte_counts;
    DmaBuffer authentication_payload;
    unsigned receive_count = 0;

    void pin_until_reboot() {
        DmaBuffer* buffers[] = {&free_ring,        &used_ring,        &status,
                                &commands,         &invalid_command,  &context,
                                &command_payloads, &management_ring,  &management_byte_counts,
                                &data_ring,        &data_byte_counts, &authentication_payload};
        for (auto* buffer : buffers)
            buffer->retain = true;
    }

    ~BootQueues() {
        if (free_ring.retain)
            return;
        for (unsigned i = 0; i < receive_count; ++i)
            page_free(align_down(receive_map.data<ReceiveDescriptors>()[i]), 1);
    }

    bool prepare(const FirmwareImage& image, const FirmwareAddresses& addresses) {
        if (!free_ring.allocate(sizeof(FreeRing)) || !used_ring.allocate(sizeof(UsedRing)) ||
            !status.allocate(sizeof(ReceiveStatus)) || !commands.allocate(sizeof(Commands)) ||
            !invalid_command.allocate(sizeof(InvalidCommand)) ||
            !context.allocate(sizeof(BootContext)) ||
            !receive_map.allocate(sizeof(ReceiveDescriptors)))
            return false;

        if (!prepare_command_ring(invalid_command.address, invalid_command.data<InvalidCommand>(),
                                  commands.data<Commands>()) ||
            !make_boot_context(image, addresses,
                               {free_ring.address, used_ring.address, status.address},
                               commands.address, context.data<BootContext>()))
            return false;

        // Keep one slot empty. The hardware write pointer is programmed after it configures RX.
        auto& ring = free_ring.data<FreeRing>();
        auto& descriptors = receive_map.data<ReceiveDescriptors>();
        // DMA slots move on reuse. Keep a separate, stable mapping for lookup and teardown.
        for (; receive_count < rx_ring_entries - 1; ++receive_count) {
            const auto address = Dma::allocate(1, Dma::pci);
            if (!address)
                return false;
            if (!encode_receive_buffer(address, receive_count + 1, descriptors[receive_count])) {
                page_free(address, 1);
                return false;
            }
            ring[receive_count] = descriptors[receive_count];
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

bool enable_registers(AdapterBoot& boot, uint16_t& original) {
    original = adapter.read16(pci_command);
    if ((original & bus_master) || !device_powered(adapter) || !interrupts_inactive(adapter)) {
        report("PCI function is not idle for startup");
        return false;
    }
    boot.command = original | memory_space | intx_disable;
    adapter.write16(pci_command, boot.command);
    if (adapter.read16(pci_command) != boot.command) {
        adapter.write16(pci_command, original);
        report("cannot enable PCI register access");
        return false;
    }
    return true;
}

FirmwareBootIo boot_io(AdapterBoot& boot) {
    return {
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
        [](void* state, unsigned id) -> uint8_t* {
            const auto& queues = static_cast<AdapterBoot*>(state)->queues;
            if (!id || id > queues.receive_count)
                return nullptr;
            return static_cast<uint8_t*>(physical(
                align_down(queues.receive_map.data<BootQueues::ReceiveDescriptors>()[id - 1])));
        },
    };
}

FirmwareBootMemory boot_memory(BootQueues& queues, FirmwareCheck check) {
    FirmwareBootMemory memory{queues.context.address, &queues.status.data<ReceiveStatus>(),
                              queues.used_ring.data<BootQueues::UsedRing>()};
    if (check >= FirmwareCheck::rescan) {
        memory.free_ring = queues.free_ring.data<BootQueues::FreeRing>();
        memory.receive_descriptors = queues.receive_map.data<BootQueues::ReceiveDescriptors>();
    }
    if (check >= FirmwareCheck::nvm) {
        memory.commands = queues.commands.data<BootQueues::Commands>();
        memory.command_payloads = &queues.command_payloads.data<CommandPayloads>();
        memory.command_dma = queues.command_payloads.address;
    }
    if (check == FirmwareCheck::peer_queue || management_exchange(check))
        memory.peer_queue = {queues.management_ring.address, queues.management_byte_counts.address};
    if (management_exchange(check)) {
        using Counts = uint16_t[transmit_byte_count_bytes / sizeof(uint16_t)];
        using Payload = uint8_t[authentication_dma_bytes];
        memory.authentication = {queues.management_ring.data<BootQueues::ManagementDescriptors>(),
                                 queues.management_byte_counts.data<Counts>(),
                                 queues.authentication_payload.data<Payload>(),
                                 queues.authentication_payload.address};
    }
    if (check == FirmwareCheck::data_probe) {
        using Counts = uint16_t[transmit_byte_count_bytes / sizeof(uint16_t)];
        memory.data_queue = {queues.data_ring.address, queues.data_byte_counts.address};
        memory.data_transmit = {queues.data_ring.data<BootQueues::ManagementDescriptors>(),
                                queues.data_byte_counts.data<Counts>(),
                                memory.authentication.payload, memory.authentication.address};
    }
    return memory;
}

bool restore_registers(BootQueues& queues, StagedImage& staged, uint16_t original, bool idle) {
    const auto restore = idle ? original : uint16_t(original | intx_disable);
    adapter.write16(pci_command, restore);
    const bool restored = adapter.read16(pci_command) == restore;
    if (!idle || !restored) {
        queues.pin_until_reboot();
        staged.retain = true;
        report("DMA buffers reserved until reboot");
    }
    return restored;
}

void launch_firmware(BootQueues& queues, StagedImage& staged, FirmwareCheck check,
                     const FirmwareImage& image, const AuthenticationTarget& target) {
    if (check >= FirmwareCheck::nvm && !queues.command_payloads.allocate(sizeof(CommandPayloads))) {
        report("command buffer allocation failed");
        return;
    }
    const bool authenticate = management_exchange(check);
    const bool peer_test = authenticate || check == FirmwareCheck::peer_queue;
    if (peer_test &&
        (!queues.management_ring.allocate(sizeof(BootQueues::ManagementDescriptors)) ||
         !queues.management_byte_counts.allocate(transmit_byte_count_bytes) ||
         !initialize_transmit_ring(queues.invalid_command.address,
                                   queues.management_ring.data<BootQueues::ManagementDescriptors>(),
                                   management_queue_entries))) {
        report("management queue allocation failed");
        return;
    }
    if (authenticate && !queues.authentication_payload.allocate(authentication_dma_bytes)) {
        report("authentication payload allocation failed");
        return;
    }
    if (check == FirmwareCheck::data_probe &&
        (!queues.data_ring.allocate(sizeof(BootQueues::ManagementDescriptors)) ||
         !queues.data_byte_counts.allocate(transmit_byte_count_bytes) ||
         !initialize_transmit_ring(queues.invalid_command.address,
                                   queues.data_ring.data<BootQueues::ManagementDescriptors>(),
                                   management_queue_entries))) {
        report("data queue allocation failed");
        return;
    }
    ScanElementStorage* elements = nullptr;
    if (authenticate || check == FirmwareCheck::passive_scan || check == FirmwareCheck::rescan) {
        elements = static_cast<ScanElementStorage*>(alloc(sizeof(ScanElementStorage)));
        if (!elements) {
            report("scan result allocation failed");
            return;
        }
    }
    AdapterBoot boot{0, queues};
    uint16_t original;
    if (!enable_registers(boot, original)) {
        release(elements);
        return;
    }
    const auto io = boot_io(boot);
    const auto memory = boot_memory(queues, check);
    const ScanChecks scan{image.antennas, check, elements, image.dual_lmac, target};
    const auto result =
        start_and_stop_quz(io, memory, check >= FirmwareCheck::scan_config ? &scan : nullptr);
    const bool restored = restore_registers(queues, staged, original, result.dma_idle);
    log("iwlwifi: %s, DMA idle=%u, PCI command restored=%u\n", result.status,
        uint64_t(result.dma_idle), uint64_t(restored));
    if (result.successful && peer_test && !restored)
        report("peer check could not restore PCI state");
    else
        report(result.status);
    if (check == FirmwareCheck::rescan)
        log("iwlwifi: completed scans=%u\n", uint64_t(result.completed_scans));
    if (check == FirmwareCheck::channel_context)
        log("iwlwifi: checked operating channels=%u\n", uint64_t(result.checked_channels));
    if (peer_test && result.peer_queue.id)
        log("iwlwifi: management queue=%u initial pointer=%u\n", uint64_t(result.peer_queue.id),
            uint64_t(result.peer_queue.write_pointer));
    if (result.association_id)
        log("iwlwifi: access point assigned AID=%u\n", uint64_t(result.association_id));
    if (result.nvm.version)
        log("iwlwifi: NVM version=%x channels=%u bands=%x TX=%x RX=%x\n",
            uint64_t(result.nvm.version), uint64_t(result.nvm.channel_count),
            uint64_t(result.nvm.bands), uint64_t(result.nvm.tx_chains),
            uint64_t(result.nvm.rx_chains));
    if (result.regulatory.country[0])
        log("iwlwifi: regulatory domain=%s permitted=%u slots=%u\n", result.regulatory.country,
            uint64_t(result.regulatory.valid_channels), uint64_t(result.regulatory.channel_slots));
    if (!peer_test && result.successful && result.dma_idle && restored &&
        result.passive.status == PassiveScan::Status::complete) {
        release(completed_scan.elements);
        completed_scan = result.passive;
        radio_channels = scan_channel_list(result.nvm, result.regulatory);
        elements = nullptr;
        const auto& passive = *passive_scan_snapshot();
        if (!scanned_adapter.info.index) {
            memcpy(scanned_adapter.info.mac, passive.station_address,
                   sizeof(passive.station_address));
            net_register(scanned_adapter, "iwlwifi", &adapter);
        }
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
    if (result.dma_idle && restored && result.alive) {
        report("adapter reset and stopped");
    }
}

bool prepare_image(const FirmwareImage& image, StagedImage& staged, BootQueues& queues) {
    if (!staged.copy(image)) {
        report("DMA staging allocation failed");
        return false;
    }
    if (!staged.matches(image)) {
        report("DMA staging readback failed");
        return false;
    }
    if (!queues.prepare(image, staged.addresses)) {
        report("boot context preparation failed");
        return false;
    }
    const auto& context = queues.context.data<BootContext>();
    log("iwlwifi: boot context dwords=%u RX=%u buffers=%u commands=%u\n", uint64_t(context.dwords),
        uint64_t(rx_ring_entries), uint64_t(queues.receive_count), uint64_t(command_ring_entries));
    log("iwlwifi: DMA staged API=%u LMAC=%u UMAC=%u paging=%u paging_bytes=%u\n",
        uint64_t(image.version[0]), uint64_t(image.regions[lmac].count),
        uint64_t(image.regions[umac].count), uint64_t(image.regions[paging].count),
        uint64_t(image.paging_bytes));
    report("firmware and boot queues staged in memory");
    return true;
}

struct RuntimeRadio {
    StagedImage staged;
    BootQueues queues;
    AdapterBoot boot{0, queues};
    FirmwareBootIo io = boot_io(boot);
    FirmwareBootMemory memory{};
    LiveScanSession session{io, memory};
    uint16_t original_pci = 0;
    ScanElementStorage* pending = nullptr;

    ~RuntimeRadio() {
        release(pending);
    }
};

RuntimeRadio* radio;

void stop_runtime(NetAdapter& device) {
    if (!radio)
        return;
    const bool idle = stop_live_quz(radio->session);
    restore_registers(radio->queues, radio->staged, radio->original_pci, idle);
    radio->~RuntimeRadio();
    release(radio);
    radio = nullptr;
    device.receive_only_diagnostic = true;
    device.info.live = false;
}

void poll_runtime(NetAdapter& device) {
    if (!radio)
        return;
    const bool active = radio->session.active;
    const auto outcome = poll_live_scan(radio->session, clock_monotonic_ns() / 1000000);
    if (outcome == ScanOutcome::pending)
        return;
    const bool complete = outcome == ScanOutcome::complete;
    if (complete) {
        release(completed_scan.elements);
        completed_scan = radio->session.scan;
        radio->pending = nullptr;
        ++completed_generation;
    } else {
        release(radio->pending);
        radio->pending = nullptr;
    }
    radio->session.scan.elements = nullptr;
    // A timeout or bad receive state leaves command and DMA ownership uncertain.
    if (!complete && outcome != ScanOutcome::rejected && outcome != ScanOutcome::aborted) {
        log("iwlwifi: stopping live scan after firmware error %u\n", uint64_t(outcome));
        stop_runtime(device);
    }
    if (active)
        wireless_scan_finished(device.info.index, complete);
}

void launch_live_firmware(const FirmwareImage& image) {
    void* storage = alloc(sizeof(RuntimeRadio));
    if (!storage) {
        report("live radio allocation failed");
        return;
    }
    auto* device = new (storage) RuntimeRadio;
    bool prepared = prepare_image(image, device->staged, device->queues);
    if (prepared && !device->queues.command_payloads.allocate(sizeof(CommandPayloads))) {
        report("command buffer allocation failed");
        prepared = false;
    }
    if (prepared && enable_registers(device->boot, device->original_pci)) {
        device->memory = boot_memory(device->queues, FirmwareCheck::live_scan);
        const auto result = start_live_quz(device->session, image.antennas);
        report(result.status);
        if (result.successful) {
            radio = device;
            memcpy(scanned_adapter.info.mac, device->session.station_address,
                   sizeof(device->session.station_address));
            if (net_register(scanned_adapter, "iwlwifi", &adapter)) {
                scanned_adapter.receive_only_diagnostic = false;
                radio_channels = device->session.channels;
                completed_scan.status = PassiveScan::Status::complete;
            } else {
                report("cannot register the live scan interface");
                stop_runtime(scanned_adapter);
            }
            return;
        }
        restore_registers(device->queues, device->staged, device->original_pci, result.dma_idle);
    }
    device->~RuntimeRadio();
    release(device);
}

void stage_firmware(const uint8_t* bytes, size_t size, FirmwareCheck check,
                    const AuthenticationTarget& target) {
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
    if (check >= FirmwareCheck::passive_scan && !image.passive_scan_supported) {
        report("firmware lacks the supported passive scan commands");
        return;
    }
    if (check == FirmwareCheck::channel_context && !image.channel_context_supported) {
        report("firmware lacks the supported operating channel commands");
        return;
    }
    if (check == FirmwareCheck::peer_queue && !image.peer_queue_supported) {
        report("firmware lacks the supported peer station and scheduler commands");
        return;
    }
    if (management_exchange(check) && !image.authentication_supported) {
        report("firmware lacks the supported authentication commands");
        return;
    }
    if (check == FirmwareCheck::live_scan) {
        launch_live_firmware(image);
        return;
    }
    StagedImage staged;
    BootQueues queues;
    if (prepare_image(image, staged, queues) && check != FirmwareCheck::stage)
        launch_firmware(queues, staged, check, image, target);
}
} // namespace

const PassiveScan* passive_scan_snapshot() {
    return completed_scan.status == PassiveScan::Status::complete ? &completed_scan : nullptr;
}

unsigned passive_scan_interface() {
    return scanned_adapter.info.index;
}

const ScanChannelList& scan_channel_inventory() {
    return radio_channels;
}

uint32_t passive_scan_generation() {
    return completed_generation;
}

bool live_scan_available() {
    return radio != nullptr;
}

int trigger_live_scan(const ScanRequest& request) {
    if (!radio)
        return -95;
    if (!scanned_adapter.info.administrative)
        return -100;
    if (radio->pending)
        return -16;
    auto* elements = static_cast<ScanElementStorage*>(alloc(sizeof(ScanElementStorage)));
    if (!elements)
        return -12;
    const int error =
        submit_live_scan(radio->session, *elements, clock_monotonic_ns() / 1000000, request);
    if (error) {
        radio->session.scan.elements = nullptr;
        release(elements);
        return error;
    }
    radio->pending = elements;
    return 0;
}

void check_firmware(bool probe_pci, FirmwareCheck check, const AuthenticationTarget& target) {
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
        stage_firmware(bytes, size, check, target);
    else {
        log("iwlwifi: firmware read failed\n");
        report("firmware read failed");
    }
    release(bytes);
}
} // namespace ax::IntelWifi
