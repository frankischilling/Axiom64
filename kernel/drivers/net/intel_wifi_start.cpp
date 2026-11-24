// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_start.cpp
 * @brief   Start AX201 QuZ firmware, receive ALIVE, and stop DMA.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * The Gen2 sequence follows Linux iwlwifi pcie/trans.c, pcie/trans-gen2.c,
 * pcie/rx.c, iwl-csr.h, and iwl-prph.h. API 77 advertises ALIVE version 6.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_start.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned hw_if = 0x00, interrupts = 0x08, interrupt_mask = 0x0c, flow_interrupts = 0x10;
constexpr unsigned reset = 0x20, gp = 0x24, gio = 0x3c, context_base = 0x40, driver_gp_clear = 0x5c;
constexpr unsigned mailbox_set = 0x88, shadow_control = 0xa8, gio_chicken = 0x100;
constexpr unsigned hpet_debug = 0x240, link_power = 0x250;
constexpr unsigned prph_write_address = 0x444, prph_read_address = 0x448;
constexpr unsigned prph_write_data = 0x44c, prph_read_data = 0x450, receive_write_pointer = 0x1c80;
constexpr unsigned command_write_pointer = 0x460;
constexpr unsigned hpm_debug = 0xa03440, hpm_power = 0xa03458, hpm_ltr_control = 0xa0348c;
constexpr unsigned hpm_ltr = 0xa03480, peripheral_write_protect = 0xa04d00, cpu_start = 0xa05c44;
constexpr uint32_t pci_owned = 1u << 22, wake_me = 1u << 27, hap_wake = 1u << 19;
constexpr uint32_t init_done = 1u << 2, access_request = 1u << 3, clock_ready = 1u << 0;
constexpr uint32_t sleeping = 1u << 4, rf_enabled = 1u << 27, software_reset = 1u << 7;
constexpr uint32_t stop_master = 1u << 9, master_disabled = 1u << 8;
constexpr uint32_t alive_interrupt = 1u, rx_interrupt = 1u << 31;
constexpr uint32_t error_interrupts = (1u << 29) | (1u << 25);

struct Registers {
    const FirmwareBootIo& io;

    uint32_t read(unsigned offset) const {
        return io.read(io.context, offset);
    }

    void write(unsigned offset, uint32_t value) const {
        io.write(io.context, offset, value);
    }

    bool delay(unsigned microseconds) const {
        return io.delay(io.context, microseconds);
    }

    bool update(unsigned offset, uint32_t set, uint32_t clear = 0) const {
        const auto value = read(offset);
        if (value == UINT32_MAX)
            return false;
        write(offset, (value & ~clear) | set);
        return true;
    }

    bool wait(unsigned offset, uint32_t mask, uint32_t value, unsigned attempts) const {
        for (unsigned i = 0; i < attempts; ++i) {
            const auto current = read(offset);
            if (current == UINT32_MAX)
                return false;
            if ((current & mask) == value)
                return true;
            if (!delay(10))
                return false;
        }
        return false;
    }

    uint32_t read_peripheral(unsigned address) const {
        write(prph_read_address, 0x03000000 | address);
        return read(prph_read_data);
    }

    void write_peripheral(unsigned address, uint32_t value) const {
        write(prph_write_address, 0x03000000 | address);
        write(prph_write_data, value);
    }
};

bool claim(const Registers& reg) {
    if (!reg.update(hw_if, pci_owned) || !reg.wait(hw_if, pci_owned, pci_owned, 5))
        return false;
    return reg.update(mailbox_set, 1u << 5);
}

bool claim_with_wake(const Registers& reg) {
    if (claim(reg))
        return true;
    const auto power = reg.read(link_power);
    if (power == UINT32_MAX)
        return false;
    reg.write(link_power, power | (1u << 31));
    if (!reg.delay(1000) || !reg.update(hw_if, wake_me)) {
        reg.write(link_power, power);
        return false;
    }
    bool owned = false;
    for (unsigned i = 0; i < 150 && !owned; ++i) {
        owned = claim(reg);
        if (!owned && !reg.delay(1000))
            break;
    }
    reg.write(link_power, power);
    return owned;
}

bool acquire_mac(const Registers& reg) {
    return reg.update(gp, init_done | access_request) && reg.delay(2) &&
           reg.wait(gp, clock_ready | sleeping, clock_ready, 2500);
}

bool reset_adapter(const Registers& reg) {
    if (!reg.update(reset, software_reset))
        return false;
    for (unsigned i = 0; i < 5; ++i)
        if (!reg.delay(1000))
            return false;
    return true;
}

const char* prepare_adapter(const Registers& reg, bool& owned) {
    if (!acquire_mac(reg))
        return "MAC clock did not start";
    const auto debug = reg.read_peripheral(hpm_debug);
    constexpr uint32_t persistence = 1u << 12;
    if (debug != UINT32_MAX && (debug & 0xfffffff0u) != 0xa5a5a5a0 && (debug & persistence)) {
        const auto protection = reg.read_peripheral(peripheral_write_protect);
        if (protection & persistence)
            return "firmware persistence is write-protected";
        reg.write_peripheral(hpm_debug, debug & ~persistence);
    }
    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned || !acquire_mac(reg))
        return "MAC did not return after reset";

    // The integrated 22000 MAC needs the power-gating sequence before the final reset.
    const auto power = reg.read_peripheral(hpm_power);
    if (power == UINT32_MAX || (power & 0xfffffff0u) == 0xa5a5a5a0)
        return "MAC power registers unavailable";
    constexpr uint32_t force_active = 1u << 10, enable_gating_and_sleep = 3;
    reg.write_peripheral(hpm_power, power | force_active);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, power | force_active | enable_gating_and_sleep);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, (power | enable_gating_and_sleep) & ~force_active);

    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned)
        return "MAC did not return after power setup";
    reg.write(interrupt_mask, 0);
    reg.write(interrupts, UINT32_MAX);
    reg.write(flow_interrupts, UINT32_MAX);
    if (!reg.update(gio_chicken, 1u << 23) || !reg.update(hpet_debug, 0xffff0000) ||
        !reg.update(hw_if, hap_wake) || !reg.update(gio, 2) || !acquire_mac(reg))
        return "MAC clock did not stabilize";
    const auto control = reg.read(gp);
    if (control == UINT32_MAX)
        return "MAC registers unavailable";
    if (!(control & rf_enabled))
        return "Wi-Fi is blocked by the hardware switch";
    reg.write(driver_gp_clear, (1u << 1) | (1u << 2));
    reg.write(shadow_control, 0x800fffff);
    // Keep the integrated MAC's ROM reads within the PCIe latency budget during boot.
    constexpr uint32_t ltr_250us = 0x80008000 | (2u << 26) | (250u << 16) | (2u << 10) | 250u;
    reg.write_peripheral(hpm_ltr_control, 0xf);
    reg.write_peripheral(hpm_ltr, ltr_250us);
    return nullptr;
}

constexpr unsigned posted_buffers = (rx_ring_entries - 1) & ~7u;

struct ReceiveReader {
    const FirmwareBootIo& io;
    const FirmwareBootMemory& memory;
    unsigned read = 0;
    size_t offset = 0;
    const uint8_t* buffer = nullptr;

    PacketRead next(FirmwarePacket& packet) {
        const unsigned closed = memory.receive_status->closed_buffer & rx_buffer_id_mask;
        if (closed < read || closed > posted_buffers)
            return PacketRead::malformed;
        // The device completes DMA before publishing the closed-buffer index.
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        for (;;) {
            if (buffer) {
                const auto result = next_firmware_packet(buffer, page_size, offset, packet);
                if (result != PacketRead::end)
                    return result;
                buffer = nullptr;
            }
            if (read == closed)
                return PacketRead::end;
            const unsigned id = memory.used_ring[read++] & rx_buffer_id_mask;
            if (!id || id > posted_buffers)
                return PacketRead::malformed;
            buffer = io.receive_buffer(io.context, id);
            if (!buffer)
                return PacketRead::malformed;
            offset = 0;
        }
    }
};

AlivePacket decode_alive(const FirmwarePacket& packet) {
    if (packet.opcode != 1 || packet.group != 0)
        return AlivePacket::missing;
    if (packet.length < 144)
        return AlivePacket::malformed;
    return packet.payload[0] == 0xfe && packet.payload[1] == 0xca ? AlivePacket::success
                                                                  : AlivePacket::rejected;
}

const char* wait_for_alive(const Registers& reg, ReceiveReader& rx) {
    bool posted = false;
    for (unsigned i = 0; i < 2000; ++i) {
        const auto cause = reg.read(interrupts);
        if (cause == UINT32_MAX || (cause & error_interrupts))
            return "firmware startup hardware error";
        if (!posted && (cause & alive_interrupt)) {
            // Firmware programs the RX engine before it raises ALIVE. Publish whole blocks of
            // eight.
            __atomic_thread_fence(__ATOMIC_RELEASE);
            reg.write(receive_write_pointer, posted_buffers);
            posted = true;
        }
        if (cause)
            reg.write(interrupts, cause);
        if (posted) {
            FirmwarePacket packet{};
            PacketRead received;
            while ((received = rx.next(packet)) == PacketRead::packet) {
                const auto alive = decode_alive(packet);
                if (alive == AlivePacket::success)
                    return nullptr;
                if (alive == AlivePacket::rejected)
                    return "firmware rejected startup";
                if (alive == AlivePacket::malformed)
                    return "invalid firmware notification";
            }
            if (received == PacketRead::malformed)
                return "invalid firmware notification";
        }
        if (!reg.delay(1000))
            return "firmware startup timer unavailable";
    }
    return posted ? "firmware ALIVE message timed out" : "firmware ALIVE interrupt timed out";
}

enum class Reply { matched, rejected, broken, timeout };
enum class WaitFor { reply, initialization, scan };

struct CommandSession {
    const Registers& reg;
    ReceiveReader& rx;
    uint16_t index = 0;
    bool init_complete = false;
    PassiveScan* passive = nullptr;

    Reply wait(uint8_t group, uint8_t opcode, uint16_t sequence, FirmwarePacket& packet,
               WaitFor event = WaitFor::reply) {
        const unsigned deadline_ms = event == WaitFor::scan ? 12000 : 2000;
        for (unsigned attempt = 0; attempt < deadline_ms; ++attempt) {
            const auto cause = reg.read(interrupts);
            const auto control = reg.read(gp);
            if (cause == UINT32_MAX || (cause & error_interrupts) || control == UINT32_MAX ||
                !(control & rf_enabled))
                return Reply::broken;
            if (cause)
                reg.write(interrupts, cause);
            PacketRead received;
            while ((received = rx.next(packet)) == PacketRead::packet) {
                if (packet.group == 0 && packet.opcode == 4)
                    init_complete = true;
                if (passive)
                    observe_passive_scan(*passive, packet);
                if (event == WaitFor::scan) {
                    if (passive->status != PassiveScan::Status::pending)
                        return Reply::matched;
                    continue;
                }
                if (event == WaitFor::initialization) {
                    if (init_complete)
                        return Reply::matched;
                    continue;
                }
                if (packet.sequence != sequence)
                    continue;
                if (packet.group == group && packet.opcode == opcode)
                    return Reply::matched;
                if (packet.group == 0 && packet.opcode == 2)
                    return Reply::rejected;
            }
            if (received == PacketRead::malformed || !reg.delay(1000))
                return Reply::broken;
        }
        return Reply::timeout;
    }

    Reply send(uint8_t group, uint8_t opcode, const uint8_t* payload, size_t bytes,
               FirmwarePacket& packet) {
        const auto& memory = rx.memory;
        const unsigned slot = index;
        if (slot >= command_ring_entries ||
            !prepare_host_command((*memory.command_payloads)[slot],
                                  memory.command_dma + slot * command_slot_bytes,
                                  memory.commands[slot], index, group, opcode, payload, bytes))
            return Reply::broken;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        reg.write(command_write_pointer, ++index);
        return wait(group, opcode, uint16_t(slot), packet);
    }
};

const char* request_nvm(CommandSession& commands, NvmInfo& info) {
    FirmwarePacket response{};
    const uint8_t init_config[4]{1u << 1};
    const uint8_t reserved[4]{};
    if (commands.send(2, 3, init_config, sizeof(init_config), response) != Reply::matched)
        return "firmware init configuration failed";
    if (commands.send(12, 0, reserved, sizeof(reserved), response) != Reply::matched)
        return "firmware NVM access completion failed";
    if (!commands.init_complete &&
        commands.wait(0, 4, 0, response, WaitFor::initialization) != Reply::matched)
        return "firmware initialization did not complete";
    if (commands.send(12, 2, reserved, sizeof(reserved), response) != Reply::matched)
        return "firmware NVM query failed";
    if (!read_nvm_v4(response, info))
        return "firmware returned invalid NVM data";
    return nullptr;
}

const char* configure_scan(CommandSession& commands, const NvmInfo& nvm,
                           const AntennaMasks& firmware) {
    const auto tx = uint8_t(nvm.tx_chains & firmware.tx);
    const auto rx = uint8_t(nvm.rx_chains & firmware.rx);
    if (!tx || !rx)
        return "firmware and NVM antenna masks do not overlap";
    // Reduced scan configuration v5. Upstream leaves mode and station fields zero.
    const uint8_t config[12]{0, 0, 0, 0, tx, 0, 0, 0, rx};
    FirmwarePacket response{};
    return commands.send(1, 0xc, config, sizeof(config), response) == Reply::matched
               ? nullptr
               : "firmware scan configuration failed";
}

const char* request_regulatory_profile(CommandSession& commands, const NvmInfo& nvm,
                                       RegulatoryProfile& profile) {
    if (!nvm.lar_enabled)
        return "firmware NVM has location-aware regulation disabled";
    // Query the active firmware profile using the NVM default code and GET_CURRENT source.
    const uint8_t request[28]{'Z', 'Z', 0x10};
    FirmwarePacket response{};
    if (commands.send(1, 0xc8, request, sizeof(request), response) != Reply::matched)
        return "firmware regulatory profile query failed";
    if (!read_regulatory_v5(response, profile))
        return "firmware returned an invalid regulatory profile";
    return profile.valid_channels ? nullptr
                                  : "firmware regulatory profile has no permitted channels";
}

const char* configure_tx_antennas(CommandSession& commands, const NvmInfo& nvm,
                                  const AntennaMasks& firmware) {
    FirmwarePacket reply{};
    const uint8_t tx_mask[4]{uint8_t(nvm.tx_chains & firmware.tx)};
    if (!tx_mask[0])
        return "firmware and NVM transmit antenna masks do not overlap";
    if (commands.send(1, 0x98, tx_mask, sizeof(tx_mask), reply) != Reply::matched)
        return "firmware TX antenna configuration failed";
    return nullptr;
}

const char* run_passive_scan(CommandSession& commands, const NvmInfo& nvm,
                             const RegulatoryProfile& regulatory, PassiveScan& scan) {
    uint8_t request[passive_request_bytes];
    if (!prepare_passive_scan(nvm, regulatory, scan, request))
        return "no permitted 2.4 or 5 GHz channels";

    // The 22000-family CSR holds optional OEM straps followed by an OTP fallback.
    auto& address = scan.station_address;
    const auto& reg = commands.reg;
    if (!decode_station_address(reg.read(0x388), reg.read(0x38c), address) &&
        !decode_station_address(reg.read(0x380), reg.read(0x384), address))
        return "adapter has no valid station MAC address";
    uint8_t mac[mac_context_bytes];
    prepare_scan_station(address, mac);
    FirmwarePacket reply{};
    if (commands.send(1, 0x28, mac, sizeof(mac), reply) != Reply::matched)
        return "firmware station context setup failed";

    commands.passive = &scan;
    const auto submitted = commands.send(1, 0xd, request, sizeof(request), reply);
    auto completed = Reply::matched;
    if (submitted == Reply::matched && scan.status == PassiveScan::Status::pending)
        completed = commands.wait(0, 0xf, 0, reply, WaitFor::scan);
    commands.passive = nullptr;
    if (submitted != Reply::matched)
        return "firmware rejected the passive scan request";
    if (completed == Reply::timeout)
        return "passive scan completion timed out";
    if (completed != Reply::matched)
        return "passive scan receive failed";
    if (scan.status == PassiveScan::Status::aborted)
        return "firmware aborted the passive scan";
    return scan.status == PassiveScan::Status::complete
               ? nullptr
               : "firmware returned an invalid scan completion";
}
} // namespace

AlivePacket read_alive_notification(const uint8_t* data, size_t length) {
    FirmwarePacket packet{};
    size_t offset = 0;
    PacketRead received;
    while ((received = next_firmware_packet(data, length, offset, packet)) == PacketRead::packet) {
        const auto alive = decode_alive(packet);
        if (alive != AlivePacket::missing)
            return alive;
    }
    return received == PacketRead::end ? AlivePacket::missing : AlivePacket::malformed;
}

FirmwareBootResult start_and_stop_quz(const FirmwareBootIo& io, const FirmwareBootMemory& memory,
                                      const ScanChecks* scan) {
    if (!memory.context_address || memory.context_address != align_down(memory.context_address) ||
        !Dma::fits(memory.context_address, sizeof(BootContext), Dma::pci) ||
        !memory.receive_status || !memory.used_ring)
        return {"invalid startup DMA addresses", false, true};
    if ((scan && !memory.commands) ||
        (memory.commands && (!memory.command_payloads || !memory.command_dma ||
                             !Dma::fits(memory.command_dma, sizeof(CommandPayloads), Dma::pci))))
        return {"invalid command DMA addresses", false, true};
    const Registers reg{io};
    if (!claim_with_wake(reg))
        return {"PCI ownership unavailable", false, true};

    bool owned = true;
    const char* error = prepare_adapter(reg, owned);
    if (!owned)
        return {error, false, true};
    const bool request_dma = error == nullptr;
    bool alive = false;
    NvmInfo info{};
    RegulatoryProfile regulatory{};
    PassiveScan passive{};
    if (scan)
        passive.elements = scan->elements;
    if (request_dma) {
        if (!io.bus_master(io.context, true)) {
            error = "PCI bus master did not enable";
        } else {
            __atomic_thread_fence(__ATOMIC_RELEASE);
            reg.write(context_base, uint32_t(memory.context_address));
            reg.write(context_base + 4, 0);
            reg.write(interrupt_mask, alive_interrupt | rx_interrupt | error_interrupts);
            reg.write_peripheral(cpu_start, 1);
            ReceiveReader rx{io, memory};
            error = wait_for_alive(reg, rx);
            alive = !error;
            if (alive && memory.commands) {
                CommandSession commands{reg, rx};
                error = request_nvm(commands, info);
                if (!error && scan && scan->check == FirmwareCheck::passive_scan)
                    error = configure_tx_antennas(commands, info, scan->antennas);
                if (!error && scan && scan->check >= FirmwareCheck::regulatory)
                    error = request_regulatory_profile(commands, info, regulatory);
                if (!error && scan)
                    error = configure_scan(commands, info, scan->antennas);
                if (!error && scan && scan->check == FirmwareCheck::passive_scan)
                    error = run_passive_scan(commands, info, regulatory, passive);
            }
        }
    }

    reg.write(interrupt_mask, 0);
    bool idle = true;
    if (request_dma) {
        const bool stopped = reg.update(reset, stop_master) &&
                             reg.wait(reset, master_disabled, master_disabled, 200);
        const bool disabled = io.bus_master(io.context, false);
        idle = stopped && disabled;
    }
    const bool reset_done = reset_adapter(reg);
    const char* success = "firmware ALIVE received";
    if (scan && scan->check == FirmwareCheck::passive_scan)
        success = "firmware passive scan complete";
    else if (scan && scan->check == FirmwareCheck::regulatory)
        success = "firmware regulatory profile and scan configuration passed";
    else if (scan)
        success = "firmware scan configuration accepted";
    else if (memory.commands)
        success = "firmware NVM read passed";
    return {error ? error : success,
            alive,
            !request_dma || (idle && reset_done),
            !error,
            info,
            regulatory,
            passive};
}
} // namespace ax::IntelWifi
