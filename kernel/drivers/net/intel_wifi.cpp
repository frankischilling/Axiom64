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
RadioStatus diagnostic;
void poll_runtime(NetAdapter&);
int send_runtime(NetAdapter&, const void*, size_t);
void stop_runtime(NetAdapter&);
void configure_runtime(NetAdapter&);
NetAdapter scanned_adapter{
    .info{.live = true, .stats{}, .wireless = true},
    .poll = poll_runtime,
    .send = send_runtime,
    .stop = stop_runtime,
    .data = nullptr,
    .receive_only_diagnostic = true,
    .administrative_changed = configure_runtime,
};

void report(const char* status) {
    const size_t length = min(strlen(status), sizeof(diagnostic.firmware) - 1);
    memcpy(diagnostic.firmware, status, length);
    diagnostic.firmware[length] = 0;
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

bool uses_data_queue(FirmwareCheck check) {
    return check == FirmwareCheck::data_probe || check == FirmwareCheck::open_link;
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
    if (uses_data_queue(check)) {
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

bool prepare_command_queues(BootQueues& queues, FirmwareCheck check) {
    if (check >= FirmwareCheck::nvm && !queues.command_payloads.allocate(sizeof(CommandPayloads))) {
        report("command buffer allocation failed");
        return false;
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
        return false;
    }
    if (authenticate && !queues.authentication_payload.allocate(authentication_dma_bytes)) {
        report("authentication payload allocation failed");
        return false;
    }
    if (uses_data_queue(check) &&
        (!queues.data_ring.allocate(sizeof(BootQueues::ManagementDescriptors)) ||
         !queues.data_byte_counts.allocate(transmit_byte_count_bytes) ||
         !initialize_transmit_ring(queues.invalid_command.address,
                                   queues.data_ring.data<BootQueues::ManagementDescriptors>(),
                                   management_queue_entries))) {
        report("data queue allocation failed");
        return false;
    }
    return true;
}

void launch_firmware(BootQueues& queues, StagedImage& staged, FirmwareCheck check,
                     const FirmwareImage& image, const AuthenticationTarget& target) {
    if (!prepare_command_queues(queues, check))
        return;
    const bool authenticate = management_exchange(check);
    const bool peer_test = authenticate || check == FirmwareCheck::peer_queue;
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
    else if (result.successful && check == FirmwareCheck::security_key && !restored)
        report("security key check could not restore PCI state");
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
    bool flush_scan_cache = false;
    bool polling = false;
    bool connectable = false;
    bool can_recover = true;
    unsigned owner_port = 0;

    ~RuntimeRadio() {
        release(pending);
    }
};

RuntimeRadio* radio;
uint8_t* live_firmware;
size_t live_firmware_size;

void stage_firmware(const uint8_t*, size_t, FirmwareCheck, const AuthenticationTarget&);

void configure_runtime(NetAdapter& device) {
    if (!radio || device.info.administrative)
        return;
    if (radio->session.active)
        radio->session.exchange.request_abort();
    submit_live_leave(radio->session, 3);
    if (device.info.carrier)
        ++completed_generation;
    device.info.carrier = device.info.writable = false;
}

bool shut_down_radio(NetAdapter& device) {
    if (!radio)
        return false;
    const bool aborted_scan = radio->session.active;
    if (const auto pending = radio->session.station.pending_bytes)
        net_tx_complete(device, pending, true);
    const bool idle = stop_live_quz(radio->session);
    const bool restored =
        restore_registers(radio->queues, radio->staged, radio->original_pci, idle);
    diagnostic.shutdown = !idle       ? "DMA stop or reset unconfirmed"
                          : !restored ? "PCI restore failed"
                                      : "complete";
    radio->~RuntimeRadio();
    release(radio);
    radio = nullptr;
    device.receive_only_diagnostic = true;
    device.info.live = false;
    device.info.carrier = false;
    device.info.writable = false;
    if (aborted_scan)
        wireless_scan_finished(device.info.index, false);
    return idle && restored;
}

void stop_runtime(NetAdapter& device) {
    shut_down_radio(device);
    release(live_firmware);
    live_firmware = nullptr;
    live_firmware_size = 0;
}

void recover_runtime(NetAdapter& device, const char* failure, unsigned phase, int result) {
    diagnostic.failure = failure;
    diagnostic.fault_phase = phase;
    diagnostic.fault_result = result;
    ++diagnostic.failures;
    const bool retry = radio && radio->can_recover;
    const bool safe = shut_down_radio(device);
    auto* bytes = live_firmware;
    const auto size = live_firmware_size;
    live_firmware = nullptr;
    live_firmware_size = 0;
    diagnostic.recovery = !safe    ? "shutdown unconfirmed"
                          : !retry ? "radio failed before completing a scan or association"
                                   : "firmware unavailable";
    if (retry && safe && bytes) {
        ++diagnostic.restart_attempts;
        log("iwlwifi: restarting firmware after runtime failure\n");
        stage_firmware(bytes, size, FirmwareCheck::live_scan, {});
        diagnostic.recovery = radio ? "restarted" : "restart failed";
        log("iwlwifi: firmware restart %s\n", radio ? "complete" : "failed");
        if (radio) {
            // Confirm progress before allowing another restart.
            radio->can_recover = false;
            live_firmware = bytes;
            live_firmware_size = size;
            return;
        }
    }
    release(bytes);
}

const AccessPoint* associated_access_point() {
    if (!radio || !radio->session.station.queue.id ||
        radio->session.leave.phase != LeavePhase::idle)
        return nullptr;
    return &radio->session.station.peer;
}

int send_runtime(NetAdapter& device, const void* bytes, size_t length) {
    if (!radio)
        return -95;
    const int error = submit_live_data(radio->session, static_cast<const uint8_t*>(bytes), length,
                                       clock_monotonic_ns() / 1000000);
    if (!error)
        device.info.writable = false;
    return error;
}

void report_join_outcome(const NetAdapter& device, const LiveScanSession& session,
                         JoinOutcome outcome) {
    const auto& join = session.join;
    diagnostic.join_result = unsigned(outcome);
    diagnostic.peer_status = join.peer_status;
    diagnostic.queue_response = join.queue_response;
    if (join.cancel_reason) {
        wireless_connection_finished(device.info.index, join.peer.bssid, 1, true, {}, {});
        return;
    }
    WirelessElements request;
    if (join.association_sent)
        request = {join.association.body + association_request_fixed_bytes,
                   join.association.length - association_request_fixed_bytes};
    const uint16_t status =
        outcome == JoinOutcome::connected ? 0 : (join.peer_status ? join.peer_status : 1);
    wireless_connection_finished(device.info.index, join.peer.bssid, status,
                                 outcome == JoinOutcome::timeout, request,
                                 {session.association_response_ies, join.response_ie_bytes});
}

void poll_runtime(NetAdapter& device) {
    if (!radio || radio->polling)
        return;
    const bool leaving = radio->session.leave.phase != LeavePhase::idle;
    if (leaving) {
        if (device.info.carrier)
            ++completed_generation;
        device.info.carrier = device.info.writable = false;
    }
    if (leaving && !radio->session.active) {
        const auto reason = radio->session.leave.reason;
        const auto from_ap = radio->session.leave.from_ap;
        const auto join_result = radio->session.leave.join_result;
        radio->polling = true;
        const auto result =
            poll_live_leave(radio->session, clock_monotonic_ns() / 1000000, &device,
                            [](void* target, size_t length, bool failed) {
                                net_tx_complete(*static_cast<NetAdapter*>(target), length, failed);
                            });
        radio->polling = false;
        if (result == LeaveOutcome::pending)
            return;
        radio->owner_port = 0;
        if (join_result != JoinOutcome::idle)
            report_join_outcome(device, radio->session, join_result);
        if (result == LeaveOutcome::failed) {
            log("iwlwifi: stopping radio after incomplete station teardown\n");
            recover_runtime(device, "teardown", unsigned(radio->session.leave.phase), int(result));
        }
        if (join_result == JoinOutcome::idle)
            wireless_disconnected(device.info.index, reason, from_ap);
        return;
    }
    if (radio->session.join.phase != JoinPhase::idle) {
        const auto result = poll_live_join(radio->session, clock_monotonic_ns() / 1000000);
        if (result == JoinOutcome::pending)
            return;
        const bool connected = result == JoinOutcome::connected;
        if (connected) {
            radio->can_recover = true;
            device.info.carrier = device.info.writable = true;
            ++completed_generation;
        }
        report_join_outcome(device, radio->session, result);
        if (!connected) {
            log("iwlwifi: join ended at phase %u with outcome %u and peer status %u\n",
                uint64_t(radio->session.join.phase), uint64_t(result),
                uint64_t(radio->session.join.peer_status));
            recover_runtime(device, "association", unsigned(radio->session.join.phase),
                            int(result));
        }
        return;
    }
    if (radio->session.station.queue.id) {
        radio->polling = true;
        const bool healthy = poll_live_station(
            radio->session, clock_monotonic_ns() / 1000000, &device,
            [](void* target, const uint8_t* bytes, size_t length) {
                net_receive(*static_cast<NetAdapter*>(target), bytes, length);
            },
            [](void* target, size_t length, bool failed) {
                auto& adapter = *static_cast<NetAdapter*>(target);
                adapter.info.writable = adapter.info.carrier;
                net_tx_complete(adapter, length, failed);
            });
        radio->polling = false;
        if (!healthy) {
            log("iwlwifi: stopping radio after station firmware failure\n");
            recover_runtime(device, "station", 0, 0);
            ++completed_generation;
            wireless_disconnected(device.info.index);
            return;
        }
        if (!radio->session.active)
            return;
    }
    const bool active = radio->session.active;
    const auto now_ms = clock_monotonic_ns() / 1000000;
    const auto outcome = poll_live_scan(radio->session, now_ms);
    if (outcome == ScanOutcome::pending)
        return;
    const bool complete = outcome == ScanOutcome::complete;
    if (complete) {
        update_scan_history(radio->session.scan, completed_scan, now_ms, associated_access_point(),
                            radio->flush_scan_cache);
        radio->can_recover = true;
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
    const bool failed =
        !complete && outcome != ScanOutcome::rejected && outcome != ScanOutcome::aborted;
    const bool lost_station = failed && radio->session.station.queue.id;
    if (failed) {
        log("iwlwifi: stopping live scan after firmware error %u\n", uint64_t(outcome));
        recover_runtime(device, active ? "scan" : "idle receive", 0, int(outcome));
    }
    if (active)
        wireless_scan_finished(device.info.index, complete);
    if (lost_station) {
        ++completed_generation;
        wireless_disconnected(device.info.index);
    }
}

void launch_live_firmware(const FirmwareImage& image, FirmwareCheck check,
                          const AuthenticationTarget& target) {
    void* storage = alloc(sizeof(RuntimeRadio));
    if (!storage) {
        report("live radio allocation failed");
        return;
    }
    auto* device = new (storage) RuntimeRadio;
    const bool open = check == FirmwareCheck::open_link;
    device->connectable = !open && image.authentication_supported;
    const auto queue_check = device->connectable ? FirmwareCheck::open_link : check;
    bool prepared = prepare_image(image, device->staged, device->queues) &&
                    prepare_command_queues(device->queues, queue_check);
    if (prepared && open) {
        device->pending = static_cast<ScanElementStorage*>(alloc(sizeof(ScanElementStorage)));
        if (!device->pending)
            report("open station scan allocation failed");
        prepared = device->pending != nullptr;
    }
    if (prepared && enable_registers(device->boot, device->original_pci)) {
        device->memory = boot_memory(device->queues, queue_check);
        const auto result =
            start_live_quz(device->session, image.antennas, open ? &target : nullptr,
                           device->pending, image.dual_lmac);
        report(result.status);
        if (result.successful) {
            device->session.security_keys = image.security_key_version == 1;
            radio = device;
            auto& info = scanned_adapter.info;
            const auto& address = device->session.station_address;
            const bool registered = info.index != 0;
            if (!registered)
                memcpy(info.mac, address, sizeof(address));
            info.carrier = info.writable = open;
            const bool admitted = registered
                                      ? !memcmp(info.mac, address, sizeof(address))
                                      : net_register(scanned_adapter, "iwlwifi", &adapter) != 0;
            if (admitted) {
                info.live = true;
                scanned_adapter.receive_only_diagnostic = false;
                radio_channels = device->session.channels;
                release(completed_scan.elements);
                new (&completed_scan) PassiveScan{};
                ++completed_generation;
                if (open) {
                    completed_scan = result.passive;
                    for (unsigned i = 0; i < completed_scan.access_point_count; ++i)
                        completed_scan.access_points[i].seen_ms = clock_monotonic_ns() / 1000000;
                    device->pending = nullptr;
                } else {
                    completed_scan.status = PassiveScan::Status::complete;
                }
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
    if (check == FirmwareCheck::security_key &&
        (!image.peer_queue_supported || image.security_key_version != 1)) {
        report("firmware lacks the required peer or security key command version");
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
    if (check == FirmwareCheck::live_scan || check == FirmwareCheck::open_link) {
        launch_live_firmware(image, check, target);
        return;
    }
    StagedImage staged;
    BootQueues queues;
    if (prepare_image(image, staged, queues) && check != FirmwareCheck::stage)
        launch_firmware(queues, staged, check, image, target);
}
} // namespace

RadioStatus radio_status() {
    RadioStatus status = diagnostic;
    status.live = radio != nullptr;
    status.authorized = radio && radio->session.station.port_authorized;
    status.recovery_image = live_firmware != nullptr;
    return status;
}

const PassiveScan* passive_scan_snapshot() {
    return completed_scan.status == PassiveScan::Status::complete ? &completed_scan : nullptr;
}

void expire_passive_scan() {
    if (radio && expire_scan_history(completed_scan, clock_monotonic_ns() / 1000000,
                                     associated_access_point()))
        ++completed_generation;
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

bool live_connect_available() {
    return radio && radio->connectable;
}

bool live_rsn_available() {
    return radio && radio->connectable && radio->session.security_keys;
}

int request_live_connection(const StationRequest& request, unsigned owner) {
    if (!live_connect_available())
        return -95;
    if (!scanned_adapter.info.administrative)
        return -100;
    expire_passive_scan();
    const int status = submit_live_join(radio->session, completed_scan, request);
    if (!status)
        radio->owner_port = owner;
    return status;
}

int request_live_disconnect(uint16_t reason, unsigned sender) {
    if (!live_connect_available())
        return -95;
    if (radio->owner_port && sender != radio->owner_port)
        return -1;
    return submit_live_leave(radio->session, reason);
}

void close_connection_owner(unsigned port) {
    if (!port || !radio || radio->owner_port != port)
        return;
    radio->owner_port = 0;
    submit_live_leave(radio->session, 3);
}

int authorize_live_station(const uint8_t (&peer)[6], bool authorized) {
    if (!live_connect_available())
        return -95;
    auto& session = radio->session;
    if (!session.station.queue.id || memcmp(session.station.peer.bssid, peer, sizeof(peer)))
        return -2;
    if (session.leave.phase != LeavePhase::idle)
        return -16;
    if (authorized && session.station.ccmp && !session.station.keys.pairwise.installed)
        return -13;
    session.station.port_authorized = authorized;
    return 0;
}

int request_live_key(const StationKeyRequest& request) {
    if (!live_connect_available())
        return -95;
    auto& device = scanned_adapter;
    if (!device.info.administrative)
        return -100;
    if (radio->polling)
        return -16;
    radio->polling = true;
    const auto result = change_station_key(
        radio->session, request, clock_monotonic_ns() / 1000000, &device,
        [](void* target, const uint8_t* bytes, size_t length) {
            net_receive(*static_cast<NetAdapter*>(target), bytes, length);
        },
        [](void* target, size_t length, bool failed) {
            auto& adapter = *static_cast<NetAdapter*>(target);
            adapter.info.writable = true;
            net_tx_complete(adapter, length, failed);
        });
    radio->polling = false;
    if (result.link_lost) {
        log("iwlwifi: stopping radio after station key failure\n");
        recover_runtime(device, "station key", 0, result.status);
        ++completed_generation;
        wireless_disconnected(device.info.index);
    }
    return result.status;
}

bool live_bss_associated(const AccessPoint& point) {
    if (!radio || !scanned_adapter.info.carrier || !radio->session.station.queue.id)
        return false;
    const auto& peer = radio->session.station.peer;
    return point.frequency_mhz == peer.frequency_mhz &&
           !memcmp(point.bssid, peer.bssid, sizeof(peer.bssid));
}

bool live_station_info(LiveStationInfo& info) {
    if (!radio || !scanned_adapter.info.carrier || !radio->session.station.queue.id ||
        radio->session.leave.phase != LeavePhase::idle)
        return false;
    const auto& station = radio->session.station;
    const unsigned index = (station.rate & 0xf) + (station.rate & 0x100 ? scan_cck_rate_count : 0);
    memcpy(info.bssid, station.peer.bssid, sizeof(info.bssid));
    info.signal_dbm = station.peer.signal_dbm;
    info.tx_rate_100kbps = station.rate && index < sizeof(scan_legacy_rates)
                               ? uint16_t(scan_legacy_rates[index] * 5)
                               : 0;
    info.authorized = station.port_authorized;
    return true;
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
    radio->flush_scan_cache = request.flush_cache;
    return 0;
}

int abort_live_scan() {
    if (!radio)
        return -95;
    if (!scanned_adapter.info.administrative)
        return -100;
    if (!radio->session.active)
        return -2;
    radio->session.exchange.request_abort();
    return 0;
}

namespace {
bool identify_firmware_device(bool start) {
    start_requested = start;
    probe = Probe::absent;
    pci_scan(probe_adapter);
    return probe == Probe::identified;
}

BootFirmware read_firmware_file(Node* file) {
    if (!file || (file->mode & 0170000) != regular_file || !file->size ||
        file->size > max_firmware_bytes) {
        log("iwlwifi: firmware missing or invalid: %s\n", firmware_file);
        report("firmware file missing or invalid");
        return {};
    }
    const size_t size = file->size;
    auto* bytes = static_cast<uint8_t*>(alloc(size));
    if (!bytes) {
        log("iwlwifi: firmware allocation failed\n");
        report("firmware allocation failed");
        return {};
    }
    if (node_read(file, 0, bytes, size) == int64_t(size))
        return {bytes, size};
    log("iwlwifi: firmware read failed\n");
    report("firmware read failed");
    release(bytes);
    return {};
}

void stage_loaded_firmware(BootFirmware& firmware, FirmwareCheck check,
                           const AuthenticationTarget& target) {
    stage_firmware(firmware.bytes, firmware.size, check, target);
    if (radio && check == FirmwareCheck::live_scan && !live_firmware) {
        live_firmware = firmware.bytes;
        live_firmware_size = firmware.size;
        firmware = {};
    }
}

void load_firmware(Node* file, FirmwareCheck check, const AuthenticationTarget& target) {
    auto firmware = read_firmware_file(file);
    if (firmware.bytes)
        stage_loaded_firmware(firmware, check, target);
    release(firmware.bytes);
}
} // namespace

BootFirmware read_boot_firmware() {
    const auto firmware = read_firmware_file(lookup(firmware_file));
    if (firmware.bytes)
        log("iwlwifi: firmware copied from boot archive bytes=%u\n", uint64_t(firmware.size));
    return firmware;
}

void check_firmware(bool probe_pci, FirmwareCheck check, const AuthenticationTarget& target,
                    BootFirmware* boot) {
    const bool start = check != FirmwareCheck::stage;
    if ((probe_pci || start) && !identify_firmware_device(start)) {
        const char* status =
            probe == Probe::absent ? "AX201 PCI function absent" : "unsupported PCI function";
        log("iwlwifi: %s\n", status);
        report(status);
        return;
    }
    if (boot && boot->bytes) {
        log("iwlwifi: using boot archive firmware\n");
        stage_loaded_firmware(*boot, check, target);
    } else {
        load_firmware(lookup(firmware_file), check, target);
    }
}

void start_if_available() {
    auto* file = lookup(firmware_file);
    if (file && identify_firmware_device(true))
        load_firmware(file, FirmwareCheck::live_scan, {});
}
} // namespace ax::IntelWifi
